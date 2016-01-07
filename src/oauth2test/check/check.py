"""
oauth2test.check.check
~~~~~~~~~~~~~~~~~~~~~~

Contains verification checks. Checks on state or content.

:copyright: (c) 2016 by Roland Hedberg.
:license: Apache2, see LICENSE for more details.

"""
import inspect
import sys

from aatest.check import Check, ERROR
from aatest.check import get_protocol_response
from oic.extension.token import JWTToken
from oic.oauth2 import message


class VerifyResponse(Check):
    """
    Checks that the last response was one of a possible set of OpenID Connect
    Responses
    """
    cid = "verify-response"
    msg = "Expected OpenID Connect response"

    def _func(self, conv):
        inst, msg = conv.events.last_item('protocol_response')
        resp_name = inst.__class__.__name__
        for rcls in self._kwargs['response_cls']:
            if resp_name == rcls:
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

        token_factory = JWTToken('T', 0, '', '', keyjar=conv.entity.keyjar)

        inst, txtmsg = conv.events.last_item('protocol_response')
        try:
            access_token = token_factory.get_info(inst['access_token'])
        except Exception:
            self._status = ERROR
            self._message = "Access token received not a JWS"
        try:
            rt = inst['refresh_token']
        except KeyError:  # this is probably OK
            pass
        else:
            try:
                refresh_token = token_factory.get_info(rt)
            except Exception:
                self._status = ERROR
                self._message = "Refresh token received not a JWS"

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
