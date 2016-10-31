import inspect
import logging
import sys

from oic.oauth2 import ErrorResponse
from oic.oauth2.message import AccessTokenResponse
from oic.extension.client import ClientInfoResponse
from oic.extension.message import TokenIntrospectionResponse
from oic.oic import ProviderConfigurationResponse

from otest import Unknown
from otest import Break
from otest.events import EV_HTTP_RESPONSE
from otest.aus.operation import Operation
from otest.aus.request import Request
from otest.aus.request import SyncPostRequest

from oauth2test.aus import oper

__author__ = 'roland'

logger = logging.getLogger(__name__)


class Discovery(Operation):
    def __init__(self, conv, inut, sh, **kwargs):
        Operation.__init__(self, conv, inut, sh, **kwargs)
        self.dynamic = True

    def run(self):
        if self.dynamic:
            self.catch_exception(self.conv.entity.provider_config,
                                 **self.op_args)
        else:
            self.conv.entity.provider_info = ProviderConfigurationResponse(
                **self.conv.entity_config["provider_info"]
            )
        self.conv.trace.response(self.conv.entity.provider_info)

    def op_setup(self):
        pass


class Registration(Request):
    def __init__(self, conv, inut, sh, **kwargs):
        Request.__init__(self, conv, inut, sh, **kwargs)

        self.dynamic = True

    def run(self):
        if self.dynamic:
            response = self.catch_exception(self.conv.entity.register,
                                            **self.req_args)
            if self.expect_error:
                 self.expected_error_response(response)
            else:
                if isinstance(response, ErrorResponse):
                    raise Break("Unexpected error response")
        else:
            self.conv.entity.store_registration_info(
                ClientInfoResponse(**self.conf.CLIENT["registration_response"]))
        self.conv.trace.response(self.conv.entity.registration_response)

    def map_profile(self, profile_map):
        for func, arg in profile_map[self.__class__][self.profile].items():
            func(self, arg)

    def op_setup(self):
        if self.dynamic:
            self.req_args.update(self.conv.entity_config["registration_info"])
            self.req_args["url"] = self.conv.entity.provider_info[
                "registration_endpoint"]
            if self.conv.entity.jwks_uri:
                self.req_args['jwks_uri'] = self.conv.entity.jwks_uri


class AccessToken(SyncPostRequest):
    request_cls = "AccessTokenRequest"
    response_cls = "AccessTokenResponse"

    def __init__(self, conv, inut, sh, **kwargs):
        SyncPostRequest.__init__(self, conv, inut, sh, **kwargs)
        self.op_args["state"] = conv.state
        self.req_args["redirect_uri"] = conv.entity.redirect_uris[0]

    def run(self):
        self.catch_exception(self._run)

    def _run(self):
        if self.skip:
            return

        self.conv.trace.info(
            "Access Token Request with op_args: {}, req_args: {}".format(
                self.op_args, self.req_args))
        atr = self.conv.entity.do_access_token_request(
            request_args=self.req_args, **self.op_args)

        if "error" in atr:
            self.conv.trace.response("Access Token response: {}".format(atr))
            return False

        self.conv.trace.response(atr)
        assert isinstance(atr, AccessTokenResponse)


class TokenIntrospection(SyncPostRequest):
    request_cls = "TokenIntrospectionRequest"
    response_cls = "TokenIntrospectionResponse"

    def __init__(self, conv, inut, sh, **kwargs):
        SyncPostRequest.__init__(self, conv, inut, sh, **kwargs)

    def op_setup(self):
        self._token = self.conv.entity.get_token(state=self.conv.state)
        self.req_args["token_type_hint"] = 'access_token'
        self.req_args['token'] = getattr(self._token, 'access_token')

    def run(self):
        self.catch_exception(self._run)

    def _run(self):
        if self.skip:
            return

        self.conv.trace.info(
            "Token Introspection Request with op_args: {}, req_args: {}".format(
                self.op_args, self.req_args))
        atr = self.conv.entity.do_token_introspection(
            request_args=self.req_args, **self.op_args)

        if "error" in atr:
            self.conv.trace.response(
                "Token Introspection response: {}".format(atr))
            return False

        self.conv.trace.response(atr)
        assert isinstance(atr, TokenIntrospectionResponse)


class TokenRevocation(SyncPostRequest):
    request_cls = "TokenRevocationRequest"
    response_cls = "Message"

    def __init__(self, conv, inut, sh, **kwargs):
        SyncPostRequest.__init__(self, conv, inut, sh, **kwargs)

    def op_setup(self):
        self._token = self.conv.entity.get_token(state=self.conv.state)
        self.req_args["token_type_hint"] = 'access_token'
        self.req_args['token'] = getattr(self._token, 'access_token')

    def run(self):
        self.catch_exception(self._run)

    def _run(self):
        if self.skip:
            return

        self.conv.trace.info(
            "Token Revocation Request with op_args: {}, req_args: {}".format(
                self.op_args, self.req_args))
        resp = self.conv.entity.do_token_revocation(
            request_args=self.req_args, **self.op_args)

        self.conv.events.store(EV_HTTP_RESPONSE, resp)
        self.conv.trace.response('HTTP response: {}'.format(resp.status_code))


class RefreshAccessToken(SyncPostRequest):
    request_cls = "RefreshAccessTokenRequest"
    response_cls = "AccessTokenResponse"


class Cache(Operation):
    pass


def factory(name):
    for fname, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj):
            if name == fname:
                return obj

    obj = oper.factory(name)
    if not obj:
        raise Unknown("Couldn't find the operation: '{}'".format(name))
    return obj
