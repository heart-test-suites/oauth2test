import os
import pkgutil

from urllib.parse import quote_plus

from oic.utils.time_util import in_a_while

from aatest.log import with_or_without_slash
from aatest import check as aa_check
from oauth2test import check as oa2_check

__author__ = 'roland'


def log_path(session, test_id=None):
    _conv = session["conv"]

    try:
        iss = _conv.entity.provider_info["issuer"]
    except (TypeError, KeyError):
        return ""
    else:
        qiss = quote_plus(iss)

    path = with_or_without_slash(os.path.join("log", qiss))
    if path is None:
        path = os.path.join("log", qiss)

    prof = ".".join(to_profile(session))

    if not os.path.isdir("%s/%s" % (path, prof)):
        os.makedirs("%s/%s" % (path, prof))

    if test_id is None:
        test_id = session["testid"]

    return "%s/%s/%s" % (path, prof, test_id)


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


def get_check(check_id):

    package = oa2_check
    prefix = package.__name__ + "."
    for importer, modname, ispkg in pkgutil.iter_modules(package.__path__,
                                                         prefix):
        module = __import__(modname, fromlist="dummy")
        chk = module.factory(check_id)
        if chk:
            return chk

    return aa_check.factory(check_id)
