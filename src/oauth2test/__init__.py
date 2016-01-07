# -*- coding: utf-8 -*-
"""
    oauth2test
    ~~~~~~~~~~

    A HEART OAuth2 AS, RP and RS test tool
    :copyright: (c) 2016 by Roland Hedberg.
    :license: APACHE 2.0, see LICENSE for more details.
"""
import json
import time
import aatest

__author__ = 'roland'
__version__ = '0.1.1'
__license__ = 'Apache 2.0'
__copyright__ = 'Copyright 2016 Roland Hedberg'

CRYPTSUPPORT = {"none": "n", "signing": "s", "encryption": "e"}


class Trace(aatest.Trace):
    @staticmethod
    def format(resp):
        _d = {"claims": resp.to_dict()}
        if resp.jws_header:
            _d["jws header parameters"] = resp.jws_header
        if resp.jwe_header:
            _d["jwe header parameters"] = resp.jwe_header
        return _d

    def response(self, resp):
        delta = time.time() - self.start
        try:
            cl_name = resp.__class__.__name__
        except AttributeError:
            cl_name = ""

        if cl_name == "IdToken":
            txt = json.dumps({"id_token": self.format(resp)},
                             sort_keys=True, indent=2, separators=(',', ': '))
            self.trace.append("%f %s: %s" % (delta, cl_name, txt))
        else:
            try:
                dat = resp.to_dict()
            except AttributeError:
                txt = resp
                self.trace.append("%f %s" % (delta, txt))
            else:
                if cl_name == "OpenIDSchema":
                    cl_name = "UserInfo"
                    if resp.jws_header or resp.jwe_header:
                        dat = self.format(resp)
                elif "id_token" in dat:
                    dat["id_token"] = self.format(resp["id_token"])

                txt = json.dumps(dat, sort_keys=True, indent=2,
                                 separators=(',', ': '))

                self.trace.append("%f %s: %s" % (delta, cl_name, txt))

