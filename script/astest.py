#!/usr/bin/env python3

import os

# from urllib.parse import urlparse

import argparse
import logging

from oic.extension.client import Client
from oic.extension.message import factory as message_factory

from otest import func
from otest.aus.client import Factory
from otest.aus.io import WebIO
from otest.aus.prof_util import ProfileHandler
from otest.aus.tool import WebTester
from otest.conf_setup import construct_app_args

from oauth2test.aus import check
from oauth2test.aus.client import make_client
from oauth2test.aus.profiles import PROFILEMAP

from requests.packages import urllib3

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
    from otest.session import SessionHandler
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
    from oauth2test.aus import profiles

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', dest='flows', action='append',
                        help='The test descriptions')
    parser.add_argument('-k', dest='insecure',
                        help='If server CA certificates should not be verified',
                        action='store_true')
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

    _path, app_args = construct_app_args(args, request, func, profiles)

    app_args.update(
        {"msg_factory": message_factory,
         'check_factory': check.factory, 'profile_handler': ProfileHandler,
         'make_entity': make_client, 'map_prof': PROFILEMAP,
         'client_factory': Factory(Client)})

    WA = WebApplication(sessionhandler=SessionHandler, webio=WebIO,
                        webtester=WebTester, check=check, webenv=app_args,
                        pick_grp=pick_grp, path=_path)

    _conf = app_args['conf']

    SRV = wsgiserver.CherryPyWSGIServer(
        ('0.0.0.0', _conf.PORT),
        SessionMiddleware(WA.application, session_opts))

    if args.tls:
        from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter

        SRV.ssl_adapter = BuiltinSSLAdapter(_conf.SERVER_CERT, _conf.SERVER_KEY,
                                            _conf.CERT_CHAIN)
        extra = " using SSL/TLS"
    else:
        extra = ""

    print(_path)
    txt = "RP server starting listening on port:%s%s" % (_conf.PORT, extra)
    LOGGER.info(txt)
    print(txt)
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
