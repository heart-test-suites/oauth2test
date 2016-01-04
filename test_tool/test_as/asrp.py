#!/usr/bin/env python3

import importlib
import json
import os
from urllib.parse import quote_plus
from urllib.parse import urlparse

import argparse
import logging
import sys

from aatest.yamlcnf import parse_yaml_conf
from aatest.utils import setup_logging

from oic.utils.keyio import build_keyjar
from oic.oic.message import factory as oic_message_factory

from oauth2test import operation
from oauth2test import func
from oauth2test.utils import get_check
from oauth2test.io import WebIO
from oauth2test.tool import WebTester

SERVER_LOG_FOLDER = "server_log"
if not os.path.isdir(SERVER_LOG_FOLDER):
    os.makedirs(SERVER_LOG_FOLDER)

def setup_common_log():
    global COMMON_LOGGER, hdlr, base_formatter
    COMMON_LOGGER = logging.getLogger("common")
    hdlr = logging.FileHandler("%s/common.log" % SERVER_LOG_FOLDER)
    base_formatter = logging.Formatter("%(asctime)s %(name)s:%(levelname)s %(message)s")
    hdlr.setFormatter(base_formatter)
    COMMON_LOGGER.addHandler(hdlr)
    COMMON_LOGGER.setLevel(logging.DEBUG)

setup_common_log()

try:
    from mako.lookup import TemplateLookup
    from oic.oic.message import factory as message_factory
    from oic.oauth2 import ResponseError
    from oic.utils import exception_trace
    from oic.utils.http_util import Redirect
    from oic.utils.http_util import get_post
    from oic.utils.http_util import BadRequest
    from oauth2test.session import SessionHandler
except Exception as ex:
    COMMON_LOGGER.exception(ex)
    raise ex

LOGGER = logging.getLogger("")


def pick_args(args, kwargs):
    return dict([(k, kwargs[k]) for k in args])


def application(environ, start_response):
    LOGGER.info("Connection from: %s" % environ["REMOTE_ADDR"])
    session = environ['beaker.session']

    path = environ.get('PATH_INFO', '').lstrip('/')
    LOGGER.info("path: %s" % path)

    webenv = session._params['webenv']

    io = WebIO(**webenv)
    io.environ = environ
    io.start_response = start_response

    sh = SessionHandler(session, **webenv)

    tester = WebTester(io, sh, **webenv)
    tester.check_factory = get_check
    #print(tester.check_factory)

    if path == "robots.txt":
        return io.static("static/robots.txt")
    elif path == "favicon.ico":
        return io.static("static/favicon.ico")
    elif path.startswith("static/"):
        return io.static(path)
    elif path.startswith("export/"):
        return io.static(path)

    if path == "":  # list
        return tester.display_test_list()
    elif "flow_names" not in session:
        sh.session_init()

    if path == "logs":
        return io.display_log("log", issuer="", profile="", testid="")
    elif path.startswith("log"):
        if path == "log" or path == "log/":
            _cc = io.conf.CLIENT
            try:
                _iss = _cc["srv_discovery_url"]
            except KeyError:
                _iss = _cc["provider_info"]["issuer"]
            parts = [quote_plus(_iss)]
        else:
            parts = []
            while path != "log":
                head, tail = os.path.split(path)
                # tail = tail.replace(":", "%3A")
                # if tail.endswith("%2F"):
                #     tail = tail[:-3]
                parts.insert(0, tail)
                path = head

        return io.display_log("log", *parts)
    elif path.startswith("tar"):
        path = path.replace(":", "%3A")
        return io.static(path)

    if path == "reset":
        sh.reset_session(sh.session)
        return io.flow_list(session)
    elif path == "pedit":
        try:
            return io.profile_edit(session)
        except Exception as err:
            return io.err_response(session, "pedit", err)
    elif path == "profile":
        return tester.set_profile(environ)
    elif path.startswith("test_info"):
        p = path.split("/")
        try:
            return io.test_info(p[1], sh.session)
        except KeyError:
            return io.not_found()
    elif path == "continue":
        return tester.cont(environ, webenv)
    elif path == "opresult":
        if tester.conv is None:
            return io.sorry_response("", "No result to report")

        return io.opresult(tester.conv, sh.session)
    # expected path format: /<testid>[/<endpoint>]
    elif path in session["flow_names"]:
        return tester.run(path, **webenv)
    elif path in ["authz_cb", "authz_post"]:
        if path == "authz_cb":
            _conv = session["conv"]
            try:
                response_mode = _conv.req.req_args["response_mode"]
            except KeyError:
                response_mode = ""

            # Check if fragment encoded
            if response_mode == "form_post":
                pass
            else:
                try:
                    response_type = _conv.req.req_args["response_type"]
                except KeyError:
                    response_type = [""]

                if response_type == [""]:  # expect anything
                    if environ["QUERY_STRING"]:
                        pass
                    else:
                        return io.opresult_fragment()
                elif response_type != ["code"]:
                    # but what if it's all returned as a query anyway ?
                    try:
                        qs = environ["QUERY_STRING"]
                    except KeyError:
                        pass
                    else:
                        _conv.trace.response("QUERY_STRING:%s" % qs)
                        _conv.query_component = qs

                    return io.opresult_fragment()

        try:
            resp = tester.async_response(webenv["conf"])
        except Exception as err:
            return io.err_response(session, "authz_cb", err)
        else:
            if resp:
                return resp
            else:
                return io.flow_list(session)
    else:
        resp = BadRequest()
        return resp(environ, start_response)


if __name__ == '__main__':
    from beaker.middleware import SessionMiddleware
    from cherrypy import wsgiserver

    parser = argparse.ArgumentParser()
    parser.add_argument('-m', dest='mailaddr')
    parser.add_argument('-o', dest='operations')
    parser.add_argument('-f', dest='flows')
    parser.add_argument('-d', dest='directory')
    parser.add_argument('-p', dest='profile')
    parser.add_argument('-P', dest='profiles')
    parser.add_argument(dest="config")
    args = parser.parse_args()

    # global ACR_VALUES
    # ACR_VALUES = CONF.ACR_VALUES

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        'session.auto': True,
        'session.timeout': 900
    }

    sys.path.insert(0, ".")
    CONF = importlib.import_module(args.config)

    setup_logging("%s/rp_%s.log" % (SERVER_LOG_FOLDER, CONF.PORT), LOGGER)

    fdef = {'Flows': {}, 'Order': [], 'Desc': []}
    cls_factories = {'': operation.factory}
    func_factory = func.factory

    spec = parse_yaml_conf(args.flows, cls_factories, func_factory)
    fdef['Flows'].update(spec['Flows'])
    for param in ['Order', 'Desc']:
        try:
            fdef[param].extend(spec[param])
        except KeyError:
            pass

    if args.profiles:
        profiles = importlib.import_module(args.profiles)
    else:
        from oidctest import profiles

    if args.operations:
        operations = importlib.import_module(args.operations)
    else:
        from oidctest import oper as operations

    if args.directory:
        _dir = args.directory
        if not _dir.endswith("/"):
            _dir += "/"
    else:
        _dir = "./"

    if args.profile:
        TEST_PROFILE = args.profile
    else:
        TEST_PROFILE = "C.T.T.ns"

    # Add own keys for signing/encrypting JWTs
    jwks, keyjar, kidd = build_keyjar(CONF.keys)

    # export JWKS
    p = urlparse(CONF.KEY_EXPORT_URL)
    f = open("."+p.path, "w")
    f.write(json.dumps(jwks))
    f.close()
    jwks_uri = p.geturl()

    LOOKUP = TemplateLookup(directories=[_dir + 'templates', _dir + 'htdocs'],
                            module_directory=_dir + 'modules',
                            input_encoding='utf-8',
                            output_encoding='utf-8')

    ENV = {"base_url": CONF.BASE, "kidd": kidd, "keyjar": keyjar,
           "jwks_uri": jwks_uri, "flows": fdef['Flows'], "conf": CONF,
           "cinfo": CONF.INFO, "order": fdef['Order'],
           "profiles": profiles, "operation": operations,
           "profile": args.profile, "msg_factory": oic_message_factory,
           "lookup": LOOKUP, "desc": fdef['Desc'], "cache": {},
           'check_factory': get_check}

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', CONF.PORT),
                                        SessionMiddleware(application,
                                                          session_opts,
                                                          webenv=ENV))

    if CONF.BASE.startswith("https"):
        from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter
        SRV.ssl_adapter = BuiltinSSLAdapter(CONF.SERVER_CERT, CONF.SERVER_KEY,
                                            CONF.CERT_CHAIN)
        extra = " using SSL/TLS"
    else:
        extra = ""

    txt = "RP server starting listening on port:%s%s" % (CONF.PORT, extra)
    LOGGER.info(txt)
    print(txt)
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
