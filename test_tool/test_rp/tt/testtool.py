import logging
import re
import sys
import traceback
from aatest.check import State, ERROR
from aatest.events import EV_REQUEST, EV_CONDITION, EV_RESPONSE

from future.backports.urllib.parse import parse_qs
from future.backports.urllib.parse import quote_plus
from future.backports.urllib.parse import urlparse

from mako.lookup import TemplateLookup
import requests

from oauth2test.provider import Provider

from oic.oauth2.provider import AuthorizationEndpoint
from oic.oauth2.provider import TokenEndpoint
from oic.extension.provider import RegistrationEndpoint
from oic.extension.provider import ClientInfoEndpoint
from oic.extension.provider import RevocationEndpoint
from oic.extension.provider import IntrospectionEndpoint
from oic.utils.http_util import NotFound, extract_from_request
from oic.utils.http_util import ServiceError
from oic.utils.http_util import Response
from oic.utils.http_util import BadRequest
from oic.utils.webfinger import OIC_ISSUER
from oic.utils.webfinger import WebFinger

__author__ = 'roland'

logger = logging.getLogger("")
LOGFILE_NAME = 'tt.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)

ROOT = './'

LOOKUP = TemplateLookup(directories=[ROOT + 'htdocs'],
                        module_directory=ROOT + 'modules',
                        input_encoding='utf-8', output_encoding='utf-8')


def store_response(response, event_db):
    event_db.store(EV_RESPONSE, response.info())


def wsgi_wrapper(environ, func, event_db, **kwargs):
    kwargs = extract_from_request(environ, kwargs)
    event_db.store(EV_REQUEST, kwargs)
    args = func(**kwargs)

    try:
        resp, state = args
        store_response(resp, event_db)
        return resp
    except TypeError:
        resp = args
        store_response(resp, event_db)
        return resp
    except Exception as err:
        logger.error("%s" % err)
        raise


# noinspection PyUnresolvedReferences
def static(path):
    logger.info("[static]sending: %s" % (path,))

    try:
        resp = Response(open(path).read())
        if path.endswith(".ico"):
            resp.add_header(('Content-Type', "image/x-icon"))
        elif path.endswith(".html"):
            resp.add_header(('Content-Type', 'text/html'))
        elif path.endswith(".json"):
            resp.add_header(('Content-Type', 'application/json'))
        elif path.endswith(".txt"):
            resp.add_header(('Content-Type', 'text/plain'))
        elif path.endswith(".css"):
            resp.add_header(('Content-Type', 'text/css'))
        else:
            resp.add_header(('Content-Type', "text/xml"))
        return resp
    except IOError:
        return NotFound(path)


def css(environ, event_db):
    try:
        info = open(environ["PATH_INFO"]).read()
        resp = Response(info)
    except (OSError, IOError):
        resp = NotFound(environ["PATH_INFO"])

    return resp


def start_page(environ, start_response, target):
    msg = open('start_page.html').read().format(target=target)
    resp = Response(msg)
    return resp(environ, start_response)


def token(environ, event_db):
    _oas = environ["oic.op"]

    return wsgi_wrapper(environ, _oas.token_endpoint, event_db)


def authorization(environ, event_db):
    _oas = environ["oic.op"]

    return wsgi_wrapper(environ, _oas.authorization_endpoint,
                        event_db)


def userinfo(environ, event_db):
    _oas = environ["oic.op"]

    return wsgi_wrapper(environ, _oas.userinfo_endpoint,
                        event_db)


def clientinfo(environ, event_db):
    _oas = environ["oic.op"]

    return wsgi_wrapper(environ, _oas.client_info_endpoint,
                        event_db)


def revocation(environ, event_db):
    _oas = environ["oic.op"]

    return wsgi_wrapper(environ, _oas.revocation_endpoint,
                        event_db)


def introspection(environ, event_db):
    _oas = environ["oic.op"]

    return wsgi_wrapper(environ, _oas.introspection_endpoint, event_db)


# noinspection PyUnusedLocal
def op_info(environ, event_db):
    _oas = environ["oic.op"]
    logger.info("op_info")
    return wsgi_wrapper(environ, _oas.providerinfo_endpoint,
                        event_db)


# noinspection PyUnusedLocal
def registration(environ, event_db):
    _oas = environ["oic.op"]

    if environ["REQUEST_METHOD"] == "POST":
        return wsgi_wrapper(environ, _oas.registration_endpoint,
                            event_db)
    elif environ["REQUEST_METHOD"] == "GET":
        return wsgi_wrapper(environ, _oas.read_registration,
                            event_db)
    else:
        return ServiceError("Method not supported")


def webfinger(environ, event_db):
    query = parse_qs(environ["QUERY_STRING"])
    _oas = environ["oic.op"]

    try:
        if query["rel"] != [OIC_ISSUER]:
            event_db.store(
                EV_CONDITION,
                State('webfinger_parameters', ERROR,
                      message='parameter rel wrong value: {}'.format(
                          query['rel'])))
            return BadRequest('Parameter value error')
        else:
            resource = query["resource"][0]
    except KeyError as err:
        event_db.store(EV_CONDITION,
                       State('webfinger_parameters', ERROR,
                             message='parameter {} missing'.format(err)))
        resp = BadRequest("Missing parameter in request")
    else:
        wf = WebFinger()
        resp = Response(wf.response(subject=resource, base=_oas.baseurl))
    return resp


ENDPOINTS = [
    AuthorizationEndpoint(authorization),
    TokenEndpoint(token),
    RegistrationEndpoint(registration),
    ClientInfoEndpoint(clientinfo),
    RevocationEndpoint(revocation),
    IntrospectionEndpoint(introspection)
]

URLS = [
    (r'^.well-known/openid-configuration', op_info),
    (r'^.well-known/webfinger', webfinger),
    (r'.+\.css$', css),
]


def add_endpoints(extra):
    global URLS

    for endp in extra:
        URLS.append(("^%s" % endp.etype, endp.func))


# publishes the OP endpoints
def application(environ, start_response):
    session = environ['beaker.session']
    path = environ.get('PATH_INFO', '').lstrip('/')
    event_db = session._params['event_db']
    event_db.store(EV_REQUEST, path)

    if path == "robots.txt":
        resp = static("static/robots.txt")
        return resp(environ, start_response)
    elif path.startswith("static/"):
        resp = static(path)
        return resp(environ, start_response)
    elif path == 'test_info':
        resp = Response(event_db.to_html())
        return resp(environ, start_response)
    elif path == '':
        session['rp'] = session._params['target']
        return start_page(environ, start_response, 'rp')
    elif path == 'rp':
        rp_resp = requests.request('GET', session['rp'], verify=False)
        resp = Response(event_db.to_html())
        return resp(environ, start_response)

    environ["oic.op"] = session._params['op']

    for regex, callback in URLS:
        match = re.search(regex, path)
        if match is not None:
            try:
                environ['oic.url_args'] = match.groups()[0]
            except IndexError:
                environ['oic.url_args'] = path

            logger.info("callback: %s" % callback)
            try:
                resp = callback(environ, event_db)
                return resp(environ, start_response)
            except Exception as err:
                print("%s" % err)
                message = traceback.format_exception(*sys.exc_info())
                print(message)
                logger.exception("%s" % err)
                resp = ServiceError("%s" % err)
                return resp(environ)

    logger.debug("unknown side: %s" % path)
    resp = NotFound("Couldn't find the side you asked for!")
    return resp(environ, start_response)


if __name__ == '__main__':
    import argparse
    from beaker.middleware import SessionMiddleware

    from cherrypy import wsgiserver
    from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter

    from setup import main_setup

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', dest='verbose', action='store_true')
    parser.add_argument('-d', dest='debug', action='store_true')
    parser.add_argument('-p', dest='port', default=80, type=int)
    parser.add_argument('-k', dest='insecure', action='store_true')
    parser.add_argument(dest="config")
    args = parser.parse_args()

    as_args, _, config = main_setup(args, LOOKUP)

    _base = "{base}:{port}/".format(base=config.baseurl, port=args.port)

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        'session.auto': True,
        'session.key': "{}.beaker.session.id".format(
            urlparse(_base).netloc.replace(":", "."))
    }

    target = config.TARGET.format(quote_plus(_base))

    add_endpoints(ENDPOINTS)
    print(target)

    op = Provider(**as_args)
    op.baseurl = _base

    # Initiate the web server
    SRV = wsgiserver.CherryPyWSGIServer(
        ('0.0.0.0', int(args.port)),
        SessionMiddleware(application, session_opts, server_cls=Provider,
                          op=op, target=target, event_db=as_args['event_db']))

    if _base.startswith("https"):
        from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter

        SRV.ssl_adapter = BuiltinSSLAdapter(config.SERVER_CERT,
                                            config.SERVER_KEY,
                                            config.CERT_CHAIN)
        extra = " using SSL/TLS"
    else:
        extra = ""

    txt = "RP test tool started. Listening on port:%s%s" % (args.port, extra)
    logger.info(txt)
    print(txt)

    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
