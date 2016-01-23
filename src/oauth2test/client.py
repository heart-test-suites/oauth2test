from oic.extension import client
from oic.utils.authn.client import CLIENT_AUTHN_METHOD


class Client(client.Client):
    def __init__(self, *args, **kwargs):
        client.Client.__init__(self, *args, **kwargs)
        self.conv = None

    def store_response(self, clinst, text):
        self.conv.events.store('protocol_response', (clinst, text))


def make_client(**kw_args):
    c_keyjar = kw_args["keyjar"].copy()
    _cli = Client(client_authn_method=CLIENT_AUTHN_METHOD, keyjar=c_keyjar)
    _cli.kid = kw_args["kidd"]
    _cli.jwks_uri = kw_args["jwks_uri"]

    try:
        _cli_info = kw_args["conf"].INFO["client"]
    except KeyError:
        pass
    else:
        for arg, val in list(_cli_info.items()):
            setattr(_cli, arg, val)

    return _cli

