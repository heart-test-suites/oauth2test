"""
    Assertion test module
    ~~~~~~~~~~~~~~~~~~~~~

    :copyright: (c) 2016 by Roland Hedberg.
    :license: APACHE 2.0, see LICENSE for more details.
"""
import json
from aatest.events import EV_PROTOCOL_RESPONSE
from future.backports.urllib.parse import parse_qs
from oic.oauth2 import message


def get_provider_info(conv):
    _pi = conv.entity.provider_info
    if not _pi:
        _pi = conv.provider_info
    return _pi


def get_protocol_response(conv, cls):
    res = []
    for msg in conv.events.get_messages(EV_PROTOCOL_RESPONSE):
        if isinstance(msg, cls):
            reply = conv.events.by_ref(msg.timestamp)
            if reply:
                res.append((reply[0], msg))
    return res


def get_id_tokens(conv):
    res = []
    # In access token responses
    for inst, msg in get_protocol_response(conv, message.AccessTokenResponse):
        _dict = json.loads(msg)
        jwt = _dict["id_token"]
        idt = inst["id_token"]
        res.append((idt, jwt))

    # implicit, id_token in authorization response
    for inst, msg in get_protocol_response(conv, message.AuthorizationResponse):
        try:
            idt = inst["id_token"]
        except KeyError:
            pass
        else:
            _info = parse_qs(msg)
            jwt = _info["id_token"][0]
            res.append((idt, jwt))

    return res