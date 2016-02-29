import logging
from urllib.parse import parse_qs

from aatest import exception_trace
from aatest import Break
from aatest.check import State
from aatest.check import OK
from aatest.events import EV_CONDITION
from aatest.events import EV_HTTP_RESPONSE
from aatest.io import eval_state
from aatest.io import safe_path
from aatest.session import Done
from aatest.summation import store_test_state
from aatest.tool import Tester
from aatest.verify import Verify

from oic.utils.http_util import Redirect
from oic.utils.http_util import Response
from oic.utils.http_util import get_post

from oauth2test import CRYPTSUPPORT
from oauth2test import Trace

from oauth2test.client import make_client
from oauth2test.conversation import Conversation

__author__ = 'roland'

logger = logging.getLogger(__name__)


def get_redirect_uris(cinfo):
    try:
        return cinfo["client"]["redirect_uris"]
    except KeyError:
        return cinfo["registered"]["redirect_uris"]


class ClTester(Tester):
    pass


class WebTester(Tester):
    def display_test_list(self):
        try:
            if self.sh.session_init():
                return self.inut.flow_list()
            else:
                try:
                    resp = Redirect("%sopresult#%s" % (
                        self.inut.conf.BASE, self.sh["testid"][0]))
                except KeyError:
                    return self.inut.flow_list()
                else:
                    return resp(self.inut.environ, self.inut.start_response)
        except Exception as err:
            exception_trace("display_test_list", err)
            return self.inut.err_response("session_setup", err)

    def set_profile(self, environ):
        info = parse_qs(get_post(environ))
        try:
            cp = self.sh["profile"].split(".")
            cp[0] = info["rtype"][0]

            crsu = []
            for name, cs in list(CRYPTSUPPORT.items()):
                try:
                    if info[name] == ["on"]:
                        crsu.append(cs)
                except KeyError:
                    pass

            if len(cp) == 3:
                if len(crsu) == 3:
                    pass
                else:
                    cp.append("".join(crsu))
            else:  # len >= 4
                cp[3] = "".join(crsu)

            try:
                if info["extra"] == ['on']:
                    if len(cp) == 3:
                        cp.extend(["", "+"])
                    elif len(cp) == 4:
                        cp.append("+")
                    elif len(cp) == 5:
                        cp[4] = "+"
                else:
                    if len(cp) == 5:
                        cp = cp[:-1]
            except KeyError:
                if len(cp) == 5:
                    cp = cp[:-1]

            # reset all test flows
            self.sh.reset_session(profile=".".join(cp))
            return self.inut.flow_list()
        except Exception as err:
            return self.inut.err_response("profile", err)

    def setup(self, test_id, cinfo, **kw_args):
        redirs = get_redirect_uris(cinfo)

        _flow = self.flows[test_id]
        _cli = make_client(**kw_args)
        self.conv = Conversation(_flow, _cli, kw_args["msg_factory"],
                                 trace_cls=Trace, callback_uris=redirs)
        #_cli.conv = self.conv
        _cli.event_store = self.conv.events
        # since webfinger is not used
        self.conv.info['issuer'] = kw_args['conf'].INFO["srv_discovery_url"]
        self.sh.session_setup(path=test_id)
        self.sh["conv"] = self.conv
        self.conv.sequence = self.sh["sequence"]
        return True

    def handle_response(self, resp, index, oper=None):
        if resp:
            self.sh["index"] = index
            if isinstance(resp, Response):
                self.conv.events.store(EV_HTTP_RESPONSE, resp)
                return resp(self.inut.environ, self.inut.start_response)
            else:
                return resp
        else:
            return None

    def store_state(self, test_id, complete):
        sess = self.sh
        sess['node'].complete = complete
        sess['node'].state = eval_state(sess['conv'].events)
        self.inut.print_info(sess, test_id)

    def fname(self, test_id):
        try:
            return safe_path(
                self.conv.entity.provider_info['issuer'],
                self.profile, test_id)
        except KeyError:
            return None

    def run_flow(self, test_id, index=0, profiles=None, conf=None):
        logger.info("<=<=<=<=< %s >=>=>=>=>" % test_id)
        self.sh["node"].complete = False
        self.conv.test_id = test_id
        self.conv.conf = conf

        if index >= len(self.conv.sequence):
            return None

        _oper = None
        for item in self.conv.sequence[index:]:
            self.sh["index"] = index
            if isinstance(item, tuple):
                cls, funcs = item
            else:
                cls = item
                funcs = {}

            logger.info("<--<-- {} --- {} -->-->".format(index, cls))
            try:
                _oper = cls(conv=self.conv, inut=self.inut, sh=self.sh,
                            profile=self.profile,test_id=test_id, conf=conf,
                            funcs=funcs, check_factory=self.chk_factory,
                            cache=self.cache)
                self.conv.operation = _oper
                _oper.setup(self.map_prof)
                resp = _oper()
            except Break:
                break
            except Exception as err:
                self.inut.store_test_info()
                store_test_state(self.sh, self.conv.events)
                return self.inut.err_response("run_sequence", err)
            else:
                rsp = self.handle_response(resp, index)
                if rsp:
                    self.inut.store_test_info()
                    store_test_state(self.sh, self.conv.events)
                    return self.inut.respond(rsp)

            index += 1

        try:
            if self.conv.flow["assert"]:
                _ver = Verify(self.chk_factory, self.conv)
                _ver.test_sequence(self.conv.flow["assert"])
        except KeyError:
            pass
        except Exception as err:
            raise

        if isinstance(_oper, Done):
            self.conv.events.store(EV_CONDITION, State('Done', status=OK))
            self.inut.store_test_info()
            store_test_state(self.sh, self.conv.events)
            self.inut.print_info(test_id, self.fname(test_id))
        else:
            self.inut.store_test_info()
            store_test_state(self.sh, self.conv.events)

    def cont(self, environ, ENV):
        query = parse_qs(environ["QUERY_STRING"])
        path = query["path"][0]
        index = int(query["index"][0])

        try:
            index = self.sh["index"]
        except KeyError:  # Cookie delete broke session
            self.setup(path, **ENV)
        except Exception as err:
            return self.inut.err_response("session_setup", err)
        else:
            self.conv = self.sh["conv"]

        index += 1

        try:
            return self.run_flow(path, ENV["conf"], index)
        except Exception as err:
            exception_trace("", err, logger)
            self.inut.print_info(path)
            return self.inut.err_response("run", err)

    def async_response(self, conf):
        index = self.sh["index"]
        item = self.sh["sequence"][index]
        self.conv = self.sh["conv"]

        if isinstance(item, tuple):
            cls, funcs = item
        else:
            cls = item

        logger.info("<--<-- {} --- {}".format(index, cls))
        resp = self.conv.operation.parse_response(self.sh["testid"],
                                                  self.inut, self.message_factory)
        if resp:
            return resp

        index += 1

        return self.run_flow(self.sh["testid"], index=index)