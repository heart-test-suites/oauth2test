from aatest.func import set_request_args
from aatest.operation import Note
from aatest.session import Done
from oauth2test.func import check_endpoint

from oauth2test.operation import AccessToken
from oauth2test.operation import AsyncAuthn
from oauth2test.operation import Discovery
from oauth2test.operation import Registration
from oauth2test.operation import SyncAuthn


__author__ = 'roland'

PMAP = {"C": "Basic",
        "I": "Implicit (id_token)",
        'D': 'Direct Access'}

PROFILEMAP = {
    Discovery: {"C": {}, "I": {}},
    Done: {"C": {}, "I": {}, "D": {}},
    Note: {"C": {}, "I": {}, "D": {}},
    SyncAuthn: {
        "C": {set_request_args: {"response_type": ["code"]},
              check_endpoint: "authorization_endpoint"},
        "I": {set_request_args: {"response_type": ["token"]}},
    },
    AsyncAuthn: {
        "C": {set_request_args: {"response_type": ["code"]}},
        "I": {set_request_args: {"response_type": ["token"]}},
    },
    AccessToken: {
        "C": {},
        "I": None,
        'D': None
    },
    Registration: {
        "C": {
            set_request_args: {
                "response_types": ["code"],
                "grant_types": ["authorization_code"]}},
        "I": {
            set_request_args: {
                "response_types": ["token"],
                "grant_types": ["implicit"],
            }}
    }
}

CRYPT = {"n": "none", "s": "signing", "e": "encryption"}
SUBPROF = {"n": "none", "s": "sign", "e": "encrypt"}
