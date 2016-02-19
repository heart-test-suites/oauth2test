from aatest import prof_util

__author__ = 'roland'


RT = {"C": "code", "T": "token", 'D': 'client_credentials'}


class ProfileHandler(prof_util.ProfileHandler):
    def to_profile(self, representation="list"):
        prof = RT[self.session["profile"]]

        if representation == "list":
            return [prof]
        elif representation == "dict":
            return {'response_type': prof}
