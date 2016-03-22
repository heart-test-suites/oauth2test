from datetime import datetime
import inspect
import sys
from jwkest import jws

from aatest.check import Check
from aatest.check import WARNING
from aatest.check import ERROR
from aatest.events import EV_HTTP_RESPONSE_HEADER

from oic.extension.message import ServerMetadata
from oic.oauth2 import AccessTokenResponse
from oic.oauth2 import ASConfigurationResponse
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import UnknownKeyType
from oic.utils.keyio import UpdateFailed

from otest.check import get_protocol_response

__author__ = 'roland'

WEEK = 86400 * 7


class VerifyCacheHeader(Check):
    """
    It is RECOMMENDED that servers provide cache information through HTTP
    headers and make the cache valid for at least one week.
    """
    cid = 'verify-cache-header'
    msg = "Verify that the information is supposed to be cached"

    def _func(self, conv):
        headers = conv.events.last_item(EV_HTTP_RESPONSE_HEADER)

        res = {}
        if not headers:
            return res

        if 'cache-control' in headers:
            if 'no-store' in headers['cache-control']:
                self._message = 'Not expected to cache'
                self._status = self._status
            elif 'no-cache' in headers['cache-control']:
                self._message = 'Not expected to cache'
                self._status = self._status
            elif 'max-age' in headers['cache-control']:
                if headers['cache-control']['max-age'] < WEEK:
                    self._message = 'Too short max-age'
                    self._status = self._status
        elif 'expires' in headers:
            #  format Thu, 01 Dec 1983 20:00:00 GMT
            d = datetime.strptime(headers['expires'],
                                  "%a, %d %b %Y %H:%M:%S %Z")
        elif 'pragma' in headers:
            if 'no-cache' in headers['pragma']:
                self._message = 'Not expected to cache'
                self._status = self._status

        return res


class VerifyTokens(Check):
    """
    It is RECOMMENDED that servers provide cache information through HTTP
    headers and make the cache valid for at least one week.
    """
    cid = 'verify-tokens'
    msg = "Verify that the tokens contains the expected claims"

    def _func(self, conv):
        # returns a list, should only be one item in the list
        response = get_protocol_response(conv, AccessTokenResponse)[0]

        res = {}
        _tok = response['access_token']
        _jwt = jws.factory(_tok)
        if _jwt:
            _keys = conv.entity.keyjar.get_issuer_keys(
                conv.entity.provider_info['issuer'])
            _json = _jwt.verify_compact(_tok, _keys)
            missing = []
            for x in ['iss', 'azp', 'sub', 'kid', 'exp', 'jti']:
                if x not in _json:
                    missing.append(x)
            if missing:
                self._message = "The following claims are missing from the " \
                                "access token: {}".format(missing)
                self._status = WARNING
        try:
            _tok = response['refresh_token']
        except KeyError:
            pass
        else:
            _jwt = jws.factory(_tok)
            if _jwt:
                missing = []
                _keys = conv.entity.keyjar.get_issuer_keys(
                    conv.entity.provider_info['issuer'])
                _json = _jwt.verify_compact(_tok, _keys)
                for x in ['iss', 'azp', 'sub', 'kid', 'exp', 'jti']:
                    if x not in _json:
                        missing.append(x)
                if missing:
                    self._message = "The following claims are missing from " \
                                    "the refresh token: {}".format(missing)
                    self._status = WARNING

        return res


class VerifyJWKS(Check):
    """
    Verify that the AS publishes it's public keys in the proper way
    """
    cid = 'verify-jwks'
    msg = "Verify that the AS publishes it's public keys in the proper way"

    def _func(self, conv):

        response = get_protocol_response(conv, ASConfigurationResponse)
        if not response:
            response = get_protocol_response(conv, ServerMetadata)

        response = response[-1]  # Should only be one but ...
        res = {}

        try:
            _jwks_uri = response['jwks_uri']
        except KeyError:
            try:
                kb = KeyBundle(response['jwks'])
            except KeyBundle:
                self._message = "Neither jwks_uri or jwks defined"
                self._status = ERROR
            except UnknownKeyType as err:
                self._message = '{}'.format(err)
                self._status = ERROR
        else:
            kb = KeyBundle(source=_jwks_uri, verify_ssl=False)
            try:
                kb.update()
            except UpdateFailed as err:
                self._message = '{}'.format(err)
                self._status = ERROR

        return res


def factory(cid):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, Check):
            try:
                if obj.cid == cid:
                    return obj
            except AttributeError:
                pass

    from otest.aus import check
    return check.factory(cid)
