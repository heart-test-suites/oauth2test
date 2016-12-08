from oic.utils.time_util import in_a_while

from otest import prof_util

from otest.func import set_request_args
from otest.func import check_endpoint
from otest.operation import Note
from otest.session import Done

from oauth2test.aus.oper import AsyncAuthn
from oauth2test.aus.oper import SyncAuthn
from oauth2test.aus.request import AccessToken
from oauth2test.aus.request import Discovery
from oauth2test.aus.request import Registration
from oauth2test.aus.request import TokenIntrospection
from oauth2test.aus.request import TokenRevocation

__author__ = 'roland'

PMAP = {"C": "Basic",
        "T": "Implicit (token)",
        'D': 'Direct Access'}

PROFILEMAP = {
    Discovery: {"C": {}, "T": {}},
    Done: {"C": {}, "T": {}, "D": {}},
    Note: {"C": {}, "T": {}, "D": {}},
    SyncAuthn: {
        "C": {set_request_args: {"response_type": ["code"]},
              check_endpoint: "authorization_endpoint"},
        "T": {set_request_args: {"response_type": ["token"]}},
    },
    AsyncAuthn: {
        "C": {set_request_args: {"response_type": ["code"]}},
        "T": {set_request_args: {"response_type": ["token"]}},
    },
    AccessToken: {
        "C": {},
        "T": None,
        'D': None
    },
    Registration: {
        "C": {
            set_request_args: {
                "response_types": ["code"],
                "grant_types": ["authorization_code"]}},
        "T": {
            set_request_args: {
                "response_types": ["token"],
                "grant_types": ["implicit"],
            }}
    },
    TokenIntrospection: {"C": {}, "T": {}, "D": {}},
    TokenRevocation: {"C": {}, "T": {}, "D": {}},
}

CRYPT = {"n": "none", "s": "signing", "e": "encryption"}
SUBPROF = {"n": "none", "s": "sign", "e": "encrypt"}

RT = {"C": "code", "D": "client cred", "T": "token"}
ATTR = ["profile", 'webfinger', 'discovery', 'registration']


def to_profile(session, representation="list"):
    """
    Translate position to name

    :param session: Session information
    :param representation: Type of profile information
    :return: dictionary
    """
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
    """

    :param session:
    :param test_id:
    :return:
    """
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


class ProfileHandler(prof_util.ProfileHandler):
    def to_profile(self, representation="list"):
        prof = RT[self.session["profile"]]

        if representation == "list":
            return [prof]
        elif representation == "dict":
            return {'response_type': prof}
