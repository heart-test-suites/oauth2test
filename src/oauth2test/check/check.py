"""
oauth2test.check.check
~~~~~~~~~~~~~~~~~~~~~~

Contains verification checks. Checks on state or content.

:copyright: (c) 2016 by Roland Hedberg.
:license: Apache2, see LICENSE for more details.

"""
import inspect
import sys

from aatest.check import Check, ERROR, WARNING
from oic.extension.token import JWTToken
from oic.utils.keyio import KeyBundle


class VerifyResponse(Check):
    """
    Checks that the last response was one of a possible set of OpenID Connect
    Responses
    """
    cid = "verify-response"
    msg = "Expected OpenID Connect response"

    def check_claims(self, inst):
        missing = []
        excess = []

        if 'claims' in self._kwargs:
            for claim in self._kwargs['claims']:
                if claim not in inst:
                    missing.append(claim)

        if 'not_claims' in self._kwargs:
            for claim in self._kwargs['not_claims']:
                if claim in inst:
                    excess.append(claim)

        if missing and excess:
            self._status = ERROR
            self._message = 'Missing claims: {}, Excess claims: {}'.format(
                missing, excess)
        elif missing:
            self._status = ERROR
            self._message = 'Missing claims: {}'.format(missing)
        elif excess:
            self._status = ERROR
            self._message = 'Missing claims: {}'.format(excess)

    def check_ava(self, inst):
        for attr, val in self._kwargs['ava'].items():
            try:
                cval = inst[attr]
            except KeyError:
                self._status = ERROR
                self._message = 'Missing claim: {}'.format(attr)
                return

            if val == cval:
                pass
            elif val in cval:
                pass
            else:
                self._status = ERROR
                self._message = 'Missing claim value: {} on {}'.format(
                    val, attr)

    def _func(self, conv):
        inst, msg = conv.events.last_item('protocol_response')
        resp_name = inst.__class__.__name__
        for rcls in self._kwargs['response_cls']:
            if resp_name == rcls:
                self.check_claims(inst)
                if 'ava' in self._kwargs:
                    self.check_ava(inst)
                return {}

        self._status = ERROR
        self._message = "{} message I didn't expect".format(resp_name)
        return {}


class VerifyAccessTokens(Check):
    """
    Check that the tokens (access and refresh) are proper signed JWT
    """
    cid = "verify-tokens"
    msg = "JWS error"

    def _func(self, conv):

        token_factory = JWTToken('T', conv.entity.keyjar, 0)

        inst, txtmsg = conv.events.last_item('protocol_response')
        try:
            token_factory.get_info(inst['access_token'])
        except Exception:
            self._status = ERROR
            self._message = "Access token received not a JWS"

        try:
            rt = inst['refresh_token']
        except KeyError:  # this is probably OK
            pass
        else:
            try:
                token_factory.get_info(rt)
            except Exception:
                self._status = ERROR
                self._message = "Refresh token received not a JWS"

        return {}


WEEK = 7 * 86400


class VerifyCacheHeader(Check):
    """
    Check that the HTTP Header contains cache information
    """
    cid = "verify-cache-header"
    msg = "Expected lifetime info through HTTP Cache Control"

    def _func(self, conv):
        item = conv.events.last_item('http response header')

        _info = {}
        for attr in ['Expires', 'Cache-Control', 'Pragma']:
            try:
                _info[attr] = item[attr]
            except KeyError:
                pass

        if _info is {}:
            self._status = WARNING
            self._message = 'No Cache control info provided'
            return {}

        try:
            _cc = [x.strip() for x in _info['Cache-Control'].split(',')]
        except KeyError:
            _cc = {}

        # Should have at least one of Expire or Cache-Control['max-age']
        if not 'Expire' in _info and not 'max-age' in _cc:
            self._status = WARNING
            self._message = 'No max age set'

        return {}


class VerifyJWS(Check):
    """
    Check that the AS publishes its keys as a proper JWKS
    """
    cid = "verify-jwks"
    msg = "Expected public keys to be exported through JWKS"

    def _func(self, conv):
        inst, txt_msg = conv.events.last_item('protocol_response')

        try:
            kb = KeyBundle(source=inst['jwks_uri'])
        except KeyError:
            self._status = ERROR
            self._message = 'Missing jwks_uri in AS configuration info'
        else:
            try:
                kb.do_remote()
            except Exception as err:
                self._status = ERROR
                self._message = err

        return {}


def factory(cid):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj) and issubclass(obj, Check):
            try:
                if obj.cid == cid:
                    return obj
            except AttributeError:
                pass

    return None
