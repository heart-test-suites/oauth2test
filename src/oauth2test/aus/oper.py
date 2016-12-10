import inspect
import logging
import os

from future.backports.urllib.parse import urlparse

from oic import rndstr

from oic.exception import IssuerMismatch
from oic.exception import PyoidcError
from oic.oauth2.message import ErrorResponse

from oic.extension.message import ServerMetadata
from oic.extension.message import ClientInfoResponse
from oic.oauth2.message import AccessTokenResponse

from otest import Break
from otest import Unknown
from otest.events import EV_PROTOCOL_RESPONSE, EV_NOOP, EV_REQUEST, OUTGOING, \
    INCOMING
from otest.prof_util import DISCOVER
from otest.prof_util import REGISTER
from otest.prof_util import WEBFINGER
from otest.aus.operation import Operation
from otest.aus.request import same_issuer
from otest.aus.request import SyncGetRequest
from otest.aus.request import AsyncGetRequest
from otest.aus.request import SyncPostRequest

import sys

__author__ = 'roland'

logger = logging.getLogger(__name__)


class SubjectMismatch(Exception):
    pass


def include(url, test_id):
    p = urlparse(url)
    if p.path[1:].startswith(test_id):
        if len(p.path[1:].split("/")) <= 1:
            return os.path.join(url, "_/_/_/normal")
        else:
            return url

    return "%s://%s/%s%s_/_/_/normal" % (p.scheme, p.netloc, test_id, p.path)


def get_id_token(responses):
    """
    Find the id_tokens issued, last one first in the list
    :param responses: A list of Response instance, text message tuples
    :return: list of IdTokens instances
    """
    res = []
    for resp, txt in responses:
        try:
            res.insert(0, resp["id_token"])
        except KeyError:
            pass
    return res


class Webfinger(Operation):
    def __init__(self, conv, inut, sh, **kwargs):
        Operation.__init__(self, conv, inut, sh, **kwargs)
        self.resource = ""
        self.profile = self.profile.split('.')
        self.dynamic = self.profile[WEBFINGER] == "T"

    def run(self):
        if not self.dynamic:
            self.conv.events.store(EV_NOOP, "WebFinger")
            self.conv.info["issuer"] = self.conf.INFO["srv_discovery_url"]
        else:
            _conv = self.conv
            issuer = _conv.entity.discover(self.resource)
            _conv.info["issuer"] = issuer
            _conv.events.store('issuer', issuer)

    def op_setup(self):
        # try:
        #     self.resource = self.op_args["resource"]
        # except KeyError:
        #     self.resource = self.conf.ISSUER+self.test_id
        pass


class Discovery(Operation):
    def __init__(self, conv, inut, sh, **kwargs):
        Operation.__init__(self, conv, inut, sh, **kwargs)
        self.profile = self.profile.split('.')
        self.dynamic = self.profile[DISCOVER] == "T"

    def run(self):
        if self.dynamic:
            self.catch_exception(self.conv.entity.provider_config,
                                 **self.op_args)
        else:
            self.conv.entity.provider_info = ServerMetadata(
                **self.conf.INFO["provider_info"]
            )

    def op_setup(self):
        # if self.dynamic:
        #     try:
        #         _issuer = include(self.op_args["issuer"], self.test_id)
        #     except KeyError:
        #         _issuer = include(self.conv.info["issuer"], self.test_id)
        #
        #     self.op_args["issuer"] = _issuer
        pass


class Registration(Operation):
    def __init__(self, conv, inut, sh, **kwargs):
        Operation.__init__(self, conv, inut, sh, **kwargs)
        self.profile = self.profile.split('.')
        self.dynamic = self.profile[REGISTER] == "T"

    def run(self):
        if self.dynamic:
            self.catch_exception(self.conv.entity.register, **self.req_args)
        else:
            self.conv.entity.store_registration_info(
                ClientInfoResponse(**self.conf.INFO["registered"]))

    def op_setup(self):
        if self.dynamic:
            self.req_args.update(self.conf.INFO["client"])
            self.req_args["url"] = self.conv.entity.provider_info[
                "registration_endpoint"]


class SyncAuthn(SyncGetRequest):
    response_cls = "AuthorizationResponse"
    request_cls = "AuthorizationRequest"

    def __init__(self, conv, inut, sh, **kwargs):
        super(SyncAuthn, self).__init__(conv, inut, sh, **kwargs)
        self.op_args["endpoint"] = conv.entity.provider_info[
            "authorization_endpoint"]

        conv.state = rndstr()
        self.req_args["state"] = conv.state
        conv.nonce = rndstr()
        self.req_args["nonce"] = conv.nonce

        # defaults
        self.req_args['scope'] = ['openid']
        self.req_args['response_type'] = 'code'

        # verify that I've got a valid access code
        # self.tests["post"].append("valid_code")

    def op_setup(self):
        self.req_args["redirect_uri"] = self.conv.extra_args['callback_uris'][0]


class AsyncAuthn(AsyncGetRequest):
    response_cls = "AuthorizationResponse"
    request_cls = "AuthorizationRequest"

    def __init__(self, conv, inut, sh, **kwargs):
        super(AsyncAuthn, self).__init__(conv, inut, sh, **kwargs)
        self.op_args["endpoint"] = conv.entity.provider_info[
            "authorization_endpoint"]

        conv.state = rndstr()
        self.req_args["state"] = conv.state
        conv.nonce = rndstr()
        self.req_args["nonce"] = conv.nonce

    def map_profile(self, profile_map):
        for func, arg in profile_map[self.__class__][self.profile].items():
            func(self, arg)

    def op_setup(self):
        self.req_args["redirect_uri"] = self.conv.extra_args['callback_uris'][0]


class AccessToken(SyncPostRequest):
    def __init__(self, conv, inut, sh, **kwargs):
        SyncPostRequest.__init__(self, conv, inut, sh, **kwargs)
        self.op_args["state"] = conv.state
        self.req_args["redirect_uri"] = conv.entity.redirect_uris[0]

    def run(self):
        self.catch_exception(self._run)

    def _run(self):
        if self.skip:
            return

        self.conv.events.store(
            EV_REQUEST,
            "op_args: {}, req_args: {}".format(self.op_args, self.req_args),
            direction=OUTGOING)
        atr = self.conv.entity.do_access_token_request(
            request_args=self.req_args, **self.op_args)

        if "error" in atr:
            self.conv.events.store(EV_PROTOCOL_RESPONSE, atr,
                                   direction=INCOMING)
            return False

        try:
            _jws_alg = atr["id_token"].jws_header["alg"]
        except (KeyError, AttributeError):
            pass
        else:
            if _jws_alg == "none":
                pass
            elif "kid" not in atr[
                "id_token"].jws_header and not _jws_alg == "HS256":
                keys = self.conv.entity.keyjar.keys_by_alg_and_usage(
                    self.conv.info["issuer"], _jws_alg, "ver")
                if len(keys) > 1:
                    raise PyoidcError("No 'kid' in id_token header!")

        if not same_issuer(self.conv.info["issuer"], atr["id_token"]["iss"]):
            raise IssuerMismatch(" {} != {}".format(self.conv.info["issuer"],
                                                    atr["id_token"]["iss"]))

        #assert isinstance(atr, AccessTokenResponse)
        return atr


class UserInfo(SyncGetRequest):
    def __init__(self, conv, inut, sh, **kwargs):
        Operation.__init__(self, conv, inut, sh, **kwargs)
        self.op_args["state"] = conv.state

    def run(self):
        args = self.op_args.copy()
        args.update(self.req_args)

        response = self.conv.entity.do_user_info_request(**args)
        if self.expect_error:
            response = self.expected_error_response(response)
        else:
            if isinstance(response, ErrorResponse):
                raise Break("Unexpected error response")

            if "_claim_sources" in response:
                user_info = self.conv.entity.unpack_aggregated_claims(response)
                user_info = self.conv.entity.fetch_distributed_claims(user_info)

            self.conv.entity.userinfo = response

        self.conv.trace.response(response)

    @staticmethod
    def _verify_subject_identifier(client, user_info):
        id_tokens = get_id_token(
            client.conv.events.get_data(EV_PROTOCOL_RESPONSE))
        if id_tokens:
            if user_info["sub"] != id_tokens[0]["sub"]:
                msg = "user_info['sub'] != id_token['sub']: '{}!={}'".format(
                    user_info["sub"], id_tokens[0]["sub"])
                raise SubjectMismatch(msg)
        return "Subject identifier ok!"


class DisplayUserInfo(Operation):
    pass


def factory(name):
    for fname, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj):
            if name == fname:
                return obj

    from otest.aus import operation

    obj = operation.factory(name)
    if not obj:
        raise Unknown("Couldn't find the operation: '{}'".format(name))
    return obj
