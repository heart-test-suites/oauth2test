from oic.utils.time_util import in_a_while

from aatest import prof_util

from aatest.func import set_request_args
from aatest.operation import Note
from aatest.session import Done

from otest.func import check_endpoint
from otest.operation import AccessToken
from otest.operation import AsyncAuthn
from otest.operation import Discovery
from otest.operation import Registration
from otest.operation import SyncAuthn


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

RT = {"C": "code", "D": "client cred", "T": "token"}
ATTR = ["profile"]


def to_profile(session, representation="list"):
    p = session["profile"].split(".")
    prof = [RT[p[0]]]

    if representation == "list":
        return prof
    elif representation == "dict":
        ret = {}
        for r in range(0, len(prof)):
            ret[ATTR[r]] = prof[r]
        return ret


def get_profile_info(session, test_id=None):
    try:
        _conv = session["conv"]
    except KeyError:
        pass
    else:
        try:
            iss = _conv.entity.provider_info["issuer"]
        except (TypeError, KeyError):
            iss = ""

        profile = to_profile(session, "dict")

        if test_id is None:
            try:
                test_id = session["testid"]
            except KeyError:
                return {}

        return {"Issuer": iss, "Profile": profile, "Test ID": test_id,
                "Test description": session["node"].desc,
                "Timestamp": in_a_while()}

    return {}


RT = {"C": "code", "T": "token", 'D': 'client_credentials'}


class ProfileHandler(prof_util.ProfileHandler):
    def to_profile(self, representation="list"):
        prof = RT[self.session["profile"]]

        if representation == "list":
            return [prof]
        elif representation == "dict":
            return {'response_type': prof}
