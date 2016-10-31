from otest.events import EV_PROTOCOL_RESPONSE
from otest.events import EV_RESPONSE

from oic.extension import client
from oic.utils.authn.client import CLIENT_AUTHN_METHOD


class Client(client.Client):
    def __init__(self, *args, **kwargs):
        client.Client.__init__(self, *args, **kwargs)
        self.conv = None

    def store_response(self, clinst, text):
        self.conv.events.store(EV_RESPONSE, text)
        self.conv.events.store(EV_PROTOCOL_RESPONSE, clinst)
        self.conv.trace.response(clinst)


def make_client(**kw_args):
    """
    Have to get own copy of keyjar

    :param kw_args:
    :return:
    """
    c_keyjar = kw_args["keyjar"].copy()
    _cli = Client(client_authn_method=CLIENT_AUTHN_METHOD, keyjar=c_keyjar)

    c_info = {'keyjar': c_keyjar}
    for arg, val in list(kw_args.items()):
        if arg in ['keyjar']:
            continue
        setattr(_cli, arg, val)
        c_info[arg] = val

    return _cli, c_info
