import functools
import inspect
import json
import logging
import os
import time
from Crypto.PublicKey import RSA
from future.backports.urllib.parse import urlparse

from jwkest.jwk import RSAKey

from aatest import RequirementsNotMet
from aatest import Unknown
from aatest import Break
from aatest import operation
from aatest.events import EV_HTTP_RESPONSE
from aatest.operation import request_with_client_http_session

from oic.extension.message import TokenIntrospectionResponse

from oic.oauth2 import rndstr, ErrorResponse
from oic.oauth2.message import AccessTokenResponse
from oic.extension.client import ClientInfoResponse
from oic.oic import ProviderConfigurationResponse
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import ec_init
from oic.utils.keyio import dump_jwks

from oauth2test.request import Request
from oauth2test.request import SyncGetRequest
from oauth2test.request import AsyncGetRequest
from oauth2test.request import SyncPostRequest
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


class Operation(operation.Operation):
    def __init__(self, conv, inut, sh, test_id='', conf=None,
                 funcs=None, check_factory=None, cache=None, profile=''):
        operation.Operation.__init__(self, conv, inut, sh, test_id,
                                     conf, funcs, check_factory, cache)

        try:
            self.profile = profile.split('.')
        except AttributeError:
            self.profile = profile

        # Monkey-patch: make sure we use the same http session (preserving
        # cookies) when fetching keys from issuers 'jwks_uri' as for the
        # rest of the test sequence
        import oic.utils.keyio

        oic.utils.keyio.request = functools.partial(
            request_with_client_http_session, self)


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
                **self.conf.INFO["provider_info"]
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
                ClientInfoResponse(**self.conf.INFO["registered"]))
        self.conv.trace.response(self.conv.entity.registration_response)

    def map_profile(self, profile_map):
        for func, arg in profile_map[self.__class__][self.profile].items():
            func(self, arg)

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
        # verify that I've got a valid access code
        self.tests["post"].append("valid_code")

    def op_setup(self):
        self.req_args["redirect_uri"] = self.conv.callback_uris[0]


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


class UpdateProviderKeys(Operation):
    def __call__(self, *args, **kwargs):
        issuer = self.conv.entity.provider_info["issuer"]
        # Update all keys
        for keybundle in self.conv.entity.keyjar.issuer_keys[issuer]:
            keybundle.update()


class RotateKey(Operation):
    def __call__(self):
        keyjar = self.conv.entity.keyjar
        self.conv.entity.original_keyjar = keyjar.copy()

        # invalidate the old key
        old_kid = self.op_args["old_kid"]
        old_key = keyjar.get_key_by_kid(old_kid)
        old_key.inactive_since = time.time()

        # setup new key
        key_spec = self.op_args["new_key"]
        typ = key_spec["type"].upper()
        if typ == "RSA":
            kb = KeyBundle(keytype=typ, keyusage=key_spec["use"])
            kb.append(RSAKey(use=key_spec["use"]).load_key(
                RSA.generate(key_spec["bits"])))
        elif typ == "EC":
            kb = ec_init(key_spec)
        else:
            Exception('Wrong key type')

        # add new key to keyjar with
        list(kb.keys())[0].kid = self.op_args["new_kid"]
        keyjar.add_kb("", kb)

        # make jwks and update file
        keys = []
        for kb in keyjar[""]:
            keys.extend(
                [k.to_dict() for k in list(kb.keys()) if not k.inactive_since])
        jwks = dict(keys=keys)
        with open(self.op_args["jwks_path"], "w") as f:
            f.write(json.dumps(jwks))


class RestoreKeyJar(Operation):
    def __call__(self):
        self.conv.entity.keyjar = self.conv.entity.original_keyjar

        # make jwks and update file
        keys = []
        for kb in self.conv.entity.keyjar[""]:
            keys.extend([k.to_dict() for k in list(kb.keys())])
        jwks = dict(keys=keys)
        with open(self.op_args["jwks_path"], "w") as f:
            f.write(json.dumps(jwks))


class ReadRegistration(SyncGetRequest):
    def op_setup(self):
        _client = self.conv.entity
        self.req_args["access_token"] = _client.registration_access_token
        self.op_args["authn_method"] = "bearer_header"
        self.op_args["endpoint"] = _client.registration_response[
            "registration_client_uri"]


class FetchKeys(Operation):
    def __call__(self):
        kb = KeyBundle(source=self.conv.entity.provider_info["jwks_uri"])
        kb.verify_ssl = False
        kb.update()

        try:
            self.conv.keybundle.append(kb)
        except AttributeError:
            self.conv.keybundle = [kb]


class RotateKeys(Operation):
    def __init__(self, conv, inut, sh, **kwargs):
        Operation.__init__(self, conv, inut, sh, **kwargs)
        self.jwk_name = "export/jwk.json"
        self.new_key = {}
        self.kid_template = "_%d"
        self.key_usage = ""

    def __call__(self):
        # find the name of the file to which the JWKS should be written
        try:
            _uri = self.conv.entity.registration_response["jwks_uri"]
        except KeyError:
            raise RequirementsNotMet("No dynamic key handling")

        r = urlparse(_uri)
        # find the old key for this key usage and mark that as inactive
        for kb in self.conv.entity.keyjar.issuer_keys[""]:
            for key in list(kb.keys()):
                if key.use in self.new_key["use"]:
                    key.inactive = True

        kid = 0
        # only one key
        _nk = self.new_key
        _typ = _nk["type"].upper()

        if _typ == "RSA":
            kb = KeyBundle(source="file://%s" % _nk["key"],
                           fileformat="der", keytype=_typ,
                           keyusage=_nk["use"])
        else:
            kb = {}

        for k in list(kb.keys()):
            k.serialize()
            k.kid = self.kid_template % kid
            kid += 1
            self.conv.entity.kid[k.use][k.kty] = k.kid
        self.conv.entity.keyjar.add_kb("", kb)

        dump_jwks(self.conv.entity.keyjar[""], r.path[1:])


class RotateSigKeys(RotateKeys):
    def __init__(self, conv, inut, sh, **kwargs):
        RotateKeys.__init__(self, conv, inut, sh, **kwargs)
        self.new_key = {"type": "RSA", "key": "../keys/second_sig.key",
                        "use": ["sig"]}
        self.kid_template = "sig%d"


class RotateEncKeys(RotateKeys):
    def __init__(self, conv, inut, sh, **kwargs):
        RotateKeys.__init__(self, conv, inut, sh, **kwargs)
        self.new_key = {"type": "RSA", "key": "../keys/second_enc.key",
                        "use": ["enc"]}
        self.kid_template = "enc%d"


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

    from aatest import operation

    obj = operation.factory(name)
    if not obj:
        raise Unknown("Couldn't find the operation: '{}'".format(name))
    return obj
