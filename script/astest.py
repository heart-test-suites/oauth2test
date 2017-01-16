#!/usr/bin/env python3
import importlib
import os

# from urllib.parse import urlparse

import argparse
import logging
import traceback
from urllib.parse import quote_plus

import sys
from oic.extension.client import Client
from oic.extension.message import factory as message_factory
from oidctest.app_conf import REST

from otest import func
from otest.aus.client import Factory
from otest.aus.handling import WebIh
from otest.aus.prof_util import ProfileHandler
from otest.aus.tool import WebTester
from otest.conf_setup import construct_app_args
from otest.utils import setup_logging

from oauth2test.aus import check
from oauth2test.aus.client import make_client

from oauth2test.aus import request
from oauth2test.aus.profiles import PROFILEMAP

from requests.packages import urllib3

urllib3.disable_warnings()

SERVER_LOG_FOLDER = "server_log"
if not os.path.isdir(SERVER_LOG_FOLDER):
    os.makedirs(SERVER_LOG_FOLDER)


def setup_common_log():
    global COMMON_logger, hdlr, base_formatter
    COMMON_logger = logging.getLogger("common")
    hdlr = logging.FileHandler("%s/common.log" % SERVER_LOG_FOLDER)
    base_formatter = logging.Formatter(
        "%(asctime)s %(name)s:%(levelname)s %(message)s")
    hdlr.setFormatter(base_formatter)
    COMMON_logger.addHandler(hdlr)
    COMMON_logger.setLevel(logging.DEBUG)


setup_common_log()

try:
    from mako.lookup import TemplateLookup
    from oic.oauth2 import ResponseError
    from oic.utils import exception_trace
    from oic.utils.http_util import get_post
    from oic.utils.http_util import Redirect
    from oic.utils.http_util import Response
    from oic.utils.http_util import BadRequest
    from otest.session import SessionHandler
except Exception as ex:
    COMMON_logger.exception(ex)
    raise ex

logger = logging.getLogger("")


def pick_args(args, kwargs):
    return dict([(k, kwargs[k]) for k in args])


def pick_grp(name):
    return name.split('-')[2]


if __name__ == '__main__':
    from beaker.middleware import SessionMiddleware
    from cherrypy import wsgiserver
    from otest.aus.app import WebApplication
    from oauth2test.aus import profiles

    parser = argparse.ArgumentParser()
    parser.add_argument('-k', dest='insecure', action='store_true')
    parser.add_argument('-i', dest='issuer')
    parser.add_argument('-f', dest='flowdir')
    parser.add_argument('-p', dest='port', type=int)
    # parser.add_argument('-P', dest='profile')
    parser.add_argument('-M', dest='makodir')
    parser.add_argument('-S', dest='staticdir')
    parser.add_argument('-s', dest='tls', action='store_true')
    parser.add_argument('-t', dest='tag')
    # parser.add_argument(
    #     '-x', dest='xport', action='store_true', help='ONLY for testing')
    parser.add_argument('-m', dest='path2port')
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

    rest = REST(None, CONF.ENT_PATH, CONF.ENT_INFO)
    if args.tag:
        qtag = quote_plus(args.tag)
    else:
        qtag = 'default'

    ent_conf = None
    try:
        ent_conf = rest.construct_config(quote_plus(args.issuer), qtag)
    except Exception as err:
        print('iss:{}, tag:{}'.format(quote_plus(args.issuer), qtag))
        for m in traceback.format_exception(*sys.exc_info()):
            print(m)
        exit()

    setup_logging("%s/rp_%s.log" % (SERVER_LOG_FOLDER, args.port), logger)
    logger.info('construct_app_args')

    display_order = [
        "Discovery", "Registration", "Authorization request", "AccessToken"]

    _path, app_args = construct_app_args(args, CONF, request, func, profiles,
                                         ent_conf, display_order=display_order)

    app_args.update(
        {"msg_factory": message_factory,
         'check_factory': check.factory, 'profile_handler': ProfileHandler,
         'make_entity': make_client, 'map_prof': PROFILEMAP,
         'client_factory': Factory(Client)})

    WA = WebApplication(sessionhandler=SessionHandler, webio=WebIh,
                        webtester=WebTester, check=check, webenv=app_args,
                        pick_grp=pick_grp, path=_path)

    _conf = app_args['conf']

    SRV = wsgiserver.CherryPyWSGIServer(
        ('0.0.0.0', args.port),
        SessionMiddleware(WA.application, session_opts))

    if args.tls:
        from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter

        SRV.ssl_adapter = BuiltinSSLAdapter(_conf.SERVER_CERT, _conf.SERVER_KEY,
                                            _conf.CERT_CHAIN)
        extra = " using SSL/TLS"
    else:
        extra = ""

    print(_path)
    txt = "AS test server starting listening on port:%s%s" % (args.port, extra)
    logger.info(txt)
    print(txt)
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
