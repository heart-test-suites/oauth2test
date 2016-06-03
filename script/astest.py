#!/usr/bin/env python3

import importlib
import json
import os

#from urllib.parse import urlparse
from future.backports.urllib.parse import urlparse

import argparse
import logging
import sys

from oic.utils.keyio import build_keyjar
from oic.extension.message import factory as message_factory

from aatest.parse_cnf import parse_json_conf
from aatest.parse_cnf import parse_yaml_conf
from aatest.utils import setup_logging

from otest import func
from otest.aus.io import WebIO
from otest.aus.prof_util import ProfileHandler
from otest.aus.tool import WebTester
from otest.rp.setup import read_path2port_map

from oauth2test.aus import check
from oauth2test.aus.client import make_client

from requests.packages import urllib3
from oauth2test.aus.profiles import PROFILEMAP

urllib3.disable_warnings()

SERVER_LOG_FOLDER = "server_log"
if not os.path.isdir(SERVER_LOG_FOLDER):
    os.makedirs(SERVER_LOG_FOLDER)


def setup_common_log():
    global COMMON_LOGGER, hdlr, base_formatter
    COMMON_LOGGER = logging.getLogger("common")
    hdlr = logging.FileHandler("%s/common.log" % SERVER_LOG_FOLDER)
    base_formatter = logging.Formatter(
        "%(asctime)s %(name)s:%(levelname)s %(message)s")
    hdlr.setFormatter(base_formatter)
    COMMON_LOGGER.addHandler(hdlr)
    COMMON_LOGGER.setLevel(logging.DEBUG)


setup_common_log()

try:
    from mako.lookup import TemplateLookup
    from oic.oauth2 import ResponseError
    from oic.utils import exception_trace
    from oic.utils.http_util import get_post
    from oic.utils.http_util import Redirect
    from oic.utils.http_util import Response
    from oic.utils.http_util import BadRequest
    from aatest.session import SessionHandler
except Exception as ex:
    COMMON_LOGGER.exception(ex)
    raise ex

LOGGER = logging.getLogger("")


def pick_args(args, kwargs):
    return dict([(k, kwargs[k]) for k in args])


def pick_grp(name):
    return name.split('-')[2]


if __name__ == '__main__':
    from beaker.middleware import SessionMiddleware
    from cherrypy import wsgiserver
    from otest.aus.app import WebApplication
    from oauth2test.aus import request

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', dest='flows', action='append',
                        help='The test descriptions')
    parser.add_argument(
        '-m', dest='path2port',
        help='Mapping between path and port used when reverse proxy is in use')
    parser.add_argument('-p', dest='profile', help='The RP profile')
    parser.add_argument('-P', dest='profiles',
                        help='The OP profile/configuration')
    parser.add_argument('-s', dest='tls', action='store_true',
                        help="Whether the server should handle SSL/TLS")
    parser.add_argument(
        '-x', dest='xport', action='store_true', help='ONLY for testing')
    parser.add_argument(dest="config")
    args = parser.parse_args()

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        'session.auto': True,
        'session.timeout': 900
    }

    sys.path.insert(0, ".")
    CONF = importlib.import_module(args.config)

    setup_logging("%s/rp_%s.log" % (SERVER_LOG_FOLDER, CONF.PORT), LOGGER)

    fdef = {'Flows': {}, 'Order': [], 'Desc': {}}
    cls_factories = {'': request.factory}
    func_factory = func.factory
    for _file in args.flows:
        if _file.endswith('.yaml'):
            spec = parse_yaml_conf(_file, cls_factories, func_factory)
        else:
            spec = parse_json_conf(_file, cls_factories, func_factory)
        fdef['Flows'].update(spec['Flows'])
        fdef['Order'].extend(spec['Order'])
        fdef['Desc'].update(spec['Desc'])

    if args.profiles:
        profiles = importlib.import_module(args.profiles)
    else:
        from oauth2test.aus import profiles

    _dir = "./"
    LOOKUP = TemplateLookup(directories=[_dir + 'templates', _dir + 'htdocs'],
                            module_directory=_dir + 'modules',
                            input_encoding='utf-8',
                            output_encoding='utf-8')

    if args.profile:
        TEST_PROFILE = args.profile
    else:
        TEST_PROFILE = "C"

    # Add own keys for signing/encrypting JWTs
    jwks, keyjar, kidd = build_keyjar(CONF.keys)

    # export JWKS
    p = urlparse(CONF.KEY_EXPORT_URL)
    f = open("." + p.path, "w")
    f.write(json.dumps(jwks))
    f.close()
    jwks_uri = p.geturl()

    if args.path2port:
        ppmap = read_path2port_map(args.path2port)
        _path = ppmap[str(CONF.PORT)]
        if args.xport:
            _port = CONF.PORT
            _base = '{}:{}/{}/'.format(CONF.BASE, str(CONF.PORT), _path)
        else:
            _base = '{}/{}/'.format(CONF.BASE, _path)
            if args.tls:
                _port = 443
            else:
                _port = 80
    else:
        _port = CONF.PORT
        _base = CONF.BASE
        _path = ''

    app_args = {}

    webenv = {"base_url": _base, "kidd": kidd, "keyjar": keyjar,
              "jwks_uri": jwks_uri, "flows": fdef['Flows'], "conf": CONF,
              "cinfo": CONF.INFO, "order": fdef['Order'],
              "profiles": profiles, "operation": request,
              "profile": args.profile, "msg_factory": message_factory,
              "lookup": LOOKUP, "desc": fdef['Desc'], "cache": {},
              'check_factory': check.factory, 'profile_handler': ProfileHandler,
              'make_entity': make_client, 'map_prof': PROFILEMAP}

    WA = WebApplication(sessionhandler=SessionHandler, webio=WebIO,
                        webtester=WebTester, check=check, webenv=webenv,
                        pick_grp=pick_grp, path=_path)

    SRV = wsgiserver.CherryPyWSGIServer(
        ('0.0.0.0', _port), SessionMiddleware(WA.application, session_opts))

    if args.tls:
        from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter

        SRV.ssl_adapter = BuiltinSSLAdapter(CONF.SERVER_CERT, CONF.SERVER_KEY,
                                            CONF.CERT_CHAIN)
        extra = " using SSL/TLS"
    else:
        extra = ""

    print(_base)
    txt = "RP server starting listening on port:%s%s" % (_port, extra)
    LOGGER.info(txt)
    print(txt)
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
