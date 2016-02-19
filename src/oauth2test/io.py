import logging
import os
from urllib.parse import unquote

from aatest import exception_trace
from aatest import Break
from aatest.events import EV_CONDITION
from aatest.io import IO
from aatest.log import with_or_without_slash

from oic.utils.http_util import NotFound
from oic.utils.http_util import Response
from oic.utils.time_util import in_a_while

from aatest.check import ERROR
from aatest.check import OK
from aatest.check import WARNING
from aatest.check import INCOMPLETE
from aatest.check import State
from aatest.summation import represent_result
from aatest.summation import store_test_state
from aatest.summation import condition
from aatest.summation import trace_output
from aatest.utils import get_test_info

from oauth2test.utils import get_profile_info

__author__ = 'roland'

logger = logging.getLogger(__name__)

TEST_RESULTS = {OK: "OK", ERROR: "ERROR", WARNING: "WARNING",
                INCOMPLETE: "INCOMPLETE"}


class WebIO(IO):
    def __init__(self, conf, flows, desc, profile_handler, profile, lookup,
                 cache=None, environ=None, start_response=None, **kwargs):
        IO.__init__(self, flows, profile, desc, profile_handler, cache,
                    **kwargs)
        # IO.__init__(self, flows=flows, profile=profile, profiles=profiles,
        #             operation=operation, desc=desc, **kwargs)
        self.conf = conf
        self.lookup = lookup
        self.environ = environ
        self.start_response = start_response

    @staticmethod
    def store_test_info(session, profile_info=None):
        _conv = session["conv"]
        _info = {
            "trace": _conv.trace,
            "events": _conv.events,
            "index": session["index"],
            "seqlen": len(session["sequence"]),
            "descr": session["node"].desc
        }

        try:
            _info["node"] = session["node"]
        except KeyError:
            pass

        if profile_info:
            _info["profile_info"] = profile_info
        else:
            try:
                _info["profile_info"] = get_profile_info(session,
                                                         session["testid"])
            except KeyError:
                pass

        session["test_info"][session["testid"]] = _info

    def flow_list(self, session):
        try:
            resp = Response(mako_template="flowlist.mako",
                            template_lookup=self.lookup,
                            headers=[])
        except Exception as err:
            logger.error(err)
            raise

        try:
            _tid = session["testid"]
        except KeyError:
            _tid = None

        self.dump_log(session, _tid)

        argv = {
            "flows": session["tests"],
            "profile": session["profile"],
            "test_info": list(session["test_info"].keys()),
            "base": self.conf.BASE,
            "headlines": self.desc,
            "testresults": TEST_RESULTS
        }

        return resp(self.environ, self.start_response, **argv)

    def profile_edit(self, session):
        resp = Response(mako_template="profile.mako",
                        template_lookup=self.lookup,
                        headers=[])
        argv = {"profile": session["profile"]}
        return resp(self.environ, self.start_response, **argv)

    def test_info(self, testid, session):
        resp = Response(mako_template="testinfo.mako",
                        template_lookup=self.lookup,
                        headers=[])

        _conv = session["conv"]
        info = get_test_info(session, testid)

        argv = {
            "profile": info["profile_info"],
            "trace": info["trace"],
            "events": info["events"],
            "result": represent_result(_conv.events).replace("\n", "<br>\n")
        }

        return resp(self.environ, self.start_response, **argv)

    def not_found(self):
        """Called if no URL matches."""
        resp = NotFound()
        return resp(self.environ, self.start_response)

    def static(self, path):
        logger.info("[static]sending: %s" % (path,))

        try:
            text = open(path, 'rb').read()
            if path.endswith(".ico"):
                self.start_response('200 OK', [('Content-Type',
                                                "image/x-icon")])
            elif path.endswith(".html"):
                self.start_response('200 OK', [('Content-Type', 'text/html')])
            elif path.endswith(".json"):
                self.start_response('200 OK', [('Content-Type',
                                                'application/json')])
            elif path.endswith(".jwt"):
                self.start_response('200 OK', [('Content-Type',
                                                'application/jwt')])
            elif path.endswith(".txt"):
                self.start_response('200 OK', [('Content-Type', 'text/plain')])
            elif path.endswith(".css"):
                self.start_response('200 OK', [('Content-Type', 'text/css')])
            else:
                self.start_response('200 OK', [('Content-Type', "text/plain")])
            return [text]
        except IOError:
            resp = NotFound()
            return resp(self.environ, self.start_response)

    def _display(self, root, issuer, profile):
        item = []
        if profile:
            path = os.path.join(root, issuer, profile).replace(":", "%3A")
            argv = {"issuer": unquote(issuer), "profile": profile}

            path = with_or_without_slash(path)
            if path is None:
                resp = Response("No saved logs")
                return resp(self.environ, self.start_response)

            for _name in os.listdir(path):
                if _name.startswith("."):
                    continue
                fn = os.path.join(path, _name)
                if os.path.isfile(fn):
                    item.append((unquote(_name), os.path.join(profile, _name)))
        else:
            if issuer:
                argv = {'issuer': unquote(issuer), 'profile': ''}
                path = os.path.join(root, issuer).replace(":", "%3A")
            else:
                argv = {'issuer': '', 'profile': ''}
                path = root

            path = with_or_without_slash(path)
            if path is None:
                resp = Response("No saved logs")
                return resp(self.environ, self.start_response)

            for _name in os.listdir(path):
                if _name.startswith("."):
                    continue
                fn = os.path.join(path, _name)
                if os.path.isdir(fn):
                    item.append((unquote(_name), os.path.join(path, _name)))

        resp = Response(mako_template="logs.mako",
                        template_lookup=self.lookup,
                        headers=[])

        item.sort()
        argv["logs"] = item
        return resp(self.environ, self.start_response, **argv)

    def display_log(self, root, issuer="", profile="", testid=""):
        logger.info(
            "display_log root: '%s' issuer: '%s', profile: '%s' testid: '%s'"
            % (
                root, issuer, profile, testid))
        if testid:
            path = os.path.join(root, issuer, profile, testid).replace(":",
                                                                       "%3A")
            return self.static(path)
        else:
            if issuer:
                return self._display(root, issuer, profile)
            else:
                resp = Response("No saved logs")
                return resp(self.environ, self.start_response)

    @staticmethod
    def get_err_type(session):
        errt = WARNING
        try:
            if session["node"].mti == {"all": "MUST"}:
                errt = ERROR
        except KeyError:
            pass
        return errt

    def log_fault(self, session, err, where, err_type=0):
        if err_type == 0:
            err_type = self.get_err_type(session)

        if "node" in session:
            if err:
                if isinstance(err, Break):
                    session["node"].state = WARNING
                else:
                    session["node"].state = err_type
            else:
                session["node"].state = err_type

        if "conv" in session:
            if err:
                if isinstance(err, str):
                    pass
                else:
                    session["conv"].trace.error("%s:%s" % (
                        err.__class__.__name__, str(err)))
                session["conv"].events.store(EV_CONDITION,
                                             State("Fault", status=ERROR,
                                                   name=err_type,
                                                   message="{}".format(err)))
            else:
                session["conv"].events.store(
                    EV_CONDITION, State(
                        "Fault", status=ERROR,
                        name=err_type,
                        message="Error in %s" % where))

    def err_response(self, session, where, err):
        if err:
            exception_trace(where, err, logger)

        self.log_fault(session, err, where)

        try:
            _tid = session["testid"]
            self.dump_log(session, _tid)
            self.store_test_info(session)
        except KeyError:
            pass

        return self.flow_list(session)

    def sorry_response(self, homepage, err):
        resp = Response(mako_template="sorry.mako",
                        template_lookup=self.lookup,
                        headers=[])
        argv = {"htmlpage": homepage,
                "error": str(err)}
        return resp(self.environ, self.start_response, **argv)

    def opresult(self, conv, session):
        store_test_state(session, conv.events)
        return self.flow_list(session)

    def opresult_fragment(self):
        resp = Response(mako_template="opresult_repost.mako",
                        template_lookup=self.lookup,
                        headers=[])
        argv = {}
        return resp(self.environ, self.start_response, **argv)

    def respond(self, resp):
        if isinstance(resp, Response):
            return resp(self.environ, self.start_response)
        else:
            return resp


SIGN = {OK: "+", WARNING: "?", ERROR: "-", INCOMPLETE: "!"}


class ClIO(IO):
    def flow_list(self, session):
        pass

    def dump_log(self, session, test_id):
        try:
            _conv = session["conv"]
        except KeyError:
            pass
        else:
            _pi = get_profile_info(session, test_id)
            if _pi:
                sline = 60 * "="
                output = ["%s: %s" % (k, _pi[k]) for k in
                          ["Issuer", "Profile",
                           "Test ID"]]
                output.append("Timestamp: %s" % in_a_while())
                output.extend(["", sline, ""])
                output.extend(trace_output(_conv.trace))
                output.extend(["", sline, ""])
                output.extend(condition(_conv.events))
                output.extend(["", sline, ""])
                # and lastly the result
                output.append(
                    "RESULT: %s" % represent_result(_conv.events))
                output.append("")

                txt = "\n".join(output)

                print(txt)
