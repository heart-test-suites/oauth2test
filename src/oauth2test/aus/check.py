from datetime import datetime
import inspect
import json
from aatest.check import Check, WARNING
from aatest.events import EV_HTTP_RESPONSE_HEADER
import sys
from jwkest import jws
from oic.oauth2 import AccessTokenResponse
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
