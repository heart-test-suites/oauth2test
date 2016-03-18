import logging
import re
import sys
import traceback
from aatest.check import State, WARNING
from aatest.check import ERROR
from aatest.conversation import Conversation
from aatest.events import EV_REQUEST
from aatest.events import EV_CONDITION
from aatest.events import EV_RESPONSE
from aatest.events import EV_PROTOCOL_REQUEST
from aatest.events import NoSuchEvent
from aatest.summation import eval_state
from aatest.summation import get_errors
from aatest.verify import Verify

from future.backports.urllib.parse import parse_qs, urlencode
from future.backports.urllib.parse import quote_plus
from future.backports.urllib.parse import urlparse

from mako.lookup import TemplateLookup
from oic import rndstr
import requests
import time

from oauth2test.check import rp_check
from oauth2test.provider import Provider
from oauth2test.parse_conf import parse_json_conf

from oic.oauth2 import message, ErrorResponse
from oic.oauth2.provider import AuthorizationEndpoint
from oic.oauth2.provider import TokenEndpoint
from oic.extension import client
from oic.extension.provider import RegistrationEndpoint
from oic.extension.provider import ClientInfoEndpoint
from oic.extension.provider import RevocationEndpoint
from oic.extension.provider import IntrospectionEndpoint
from oic.utils.http_util import NotFound
from oic.utils.http_util import extract_from_request
from oic.utils.http_util import ServiceError
from oic.utils.http_util import Response
from oic.utils.http_util import BadRequest
from oic.utils.webfinger import OIC_ISSUER
from oic.utils.webfinger import WebFinger

from requests.packages import urllib3

urllib3.disable_warnings()

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


class Instances(object):
    def __init__(self, as_args, baseurl):
        self._db = {}
        self.as_args = as_args
        self.base_url = baseurl

    def remove_old(self):
        now = time.time()

        for key, val in self._db.items():
            if now - val['ts'] > 43200:
                del self._db[key]

    def new_map(self, sid=''):
        if not sid:
            sid = rndstr(16)

        op = Provider(**self.as_args)

        op.baseurl = '{}{}'.format(self.base_url, sid)

        _conv = Conversation(None, op, None)
        _conv.events = as_args['event_db']
        op.trace = _conv.trace

        self._db[sid] = {'op': op, 'conv': _conv, 'ts': time.time()}

        return sid

    def __getitem__(self, item):
        return self._db[item]


def run_assertions(op_env, testspecs, conversation):
    try:
        req = conversation.events.last_item(EV_PROTOCOL_REQUEST)
    except NoSuchEvent:
        pass
    else:
        _ver = Verify(None, conversation)
        _ver.test_sequence(
            testspecs[op_env['test_id']][req.__class__.__name__]["assert"])


def store_response(response, event_db):
    event_db.store(EV_RESPONSE, response.info())


def wsgi_wrapper(environ, func, event_db, **kwargs):
    kwargs = extract_from_request(environ, kwargs)
    if kwargs['request']:
        event_db.store(EV_REQUEST, kwargs['request'])
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


# def start_page(environ, start_response, target, keys):
#     base, key_list, test_spec, test_info
#     msg = open('start_page.html').read().format(target=target)
#     resp = Response(msg)
#     return resp(environ, start_response)
def start_page(target, lookup, test_spec):
    resp = Response(mako_template="test_list.mako",
                    template_lookup=lookup,
                    headers=[])

    key_list = list(test_spec.keys())
    key_list.sort()

    argv = {
        # "base": target,
        "key_list": key_list,
        "test_spec": test_spec,
        "test_info": {}
    }

    return resp, argv


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


def add_endpoints(extra):
    global URLS

    for endp in extra:
        URLS.append(("^%s" % endp.etype, endp.func))


# publishes the OP endpoints
def application(environ, start_response):
    session = environ['beaker.session']
    path = environ.get('PATH_INFO', '').lstrip('/')

    event_db = session._params['event_db']
    testspecs = session._params['test_specs']

    if path == "robots.txt":
        resp = static("static/robots.txt")
        return resp(environ, start_response)
    elif path.startswith("static/"):
        resp = static(path)
        return resp(environ, start_response)
    elif path == '':
        sid = INST.new_map()
        INST.remove_old()
        info = INST[sid]

        resp = Response(mako_template="test.mako",
                        template_lookup=session._params['lookup'],
                        headers=[])

        kwargs = {
            'events': [],
            'id': sid,
            'start_page': '',
            'params': '',
            'issuer': info['op'].baseurl,
            'http_result': ''
        }
        return resp(environ, start_response, **kwargs)
    elif path == 'rp':
        qs = parse_qs(environ["QUERY_STRING"])
        # session._params['op_env']['test_id'] = tid

        # Modify the OP configuration
        # if 'setup' in testspecs[tid] and testspecs[tid]['setup']:
        #     for func, args in testspecs[tid]['setup'].items():
        #         func(_oas, args)
        sid = qs['id'][0]
        try:
            info = INST[sid]
        except KeyError:
            INST.new_map(sid)
            info = INST[sid]

        _conv = info['conv']
        _oas = info['op']

        session._params['op_env']['test_id'] = 'default'

        _params = qs['params'][0]
        _params = _params.replace('<issuer>', _oas.baseurl)
        args = dict([p.split('=') for p in _params.split('&')])
        url = qs['start_page'][0] + '?' + urlencode(args)
        try:
            rp_resp = requests.request('GET', url, verify=False)
        except Exception as err:
            resp = ServiceError(err)
            return resp(environ, start_response)

        if rp_resp.status_code != 200:
            result = '{}:{}'.format(rp_resp.status_code, rp_resp.text)
        else:
            result = ""

        # How to recognize something went wrong ?
        resp = Response(mako_template="test.mako",
                        template_lookup=session._params['lookup'],
                        headers=[])
        kwargs = {
            'http_result': result,
            'events': _conv.events,
            'id': qs['id'][0],
            'start_page': qs['start_page'][0],
            'params': qs['params'][0],
            'issuer': _oas.baseurl
        }
        return resp(environ, start_response, **kwargs)

    sid, _path = path.split('/', 1)
    info = INST[sid]
    environ["oic.op"] = info['op']
    conversation = info['conv']
    event_db.store('path', _path)

    for regex, callback in URLS:
        match = re.search(regex, _path)
        if match is not None:
            try:
                environ['oic.url_args'] = match.groups()[0]
            except IndexError:
                environ['oic.url_args'] = _path

            logger.info("callback: %s" % callback)
            try:
                resp = callback(environ, event_db)
                # assertion checks
                run_assertions(session._params['op_env'], testspecs,
                               conversation)
                if eval_state(conversation.events) > WARNING:
                    err_desc = get_errors(conversation.events)
                    err_msg = ErrorResponse(error='invalid_request',
                                            error_description=err_desc)
                    resp = BadRequest(err_msg.to_json())
                    return resp(environ, start_response)

                return resp(environ, start_response)
            except Exception as err:
                print("%s" % err)
                print(traceback.format_exception(*sys.exc_info()))
                logger.exception("%s" % err)
                resp = ServiceError("%s" % err)
                return resp(environ, start_response)

    logger.debug("unknown side: %s" % path)
    resp = NotFound("Couldn't find the side you asked for!")
    return resp(environ, start_response)


if __name__ == '__main__':
    import argparse
    from beaker.middleware import SessionMiddleware

    from cherrypy import wsgiserver
    from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter

    from oauth2test.setup.rptt import main_setup

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', dest='verbose', action='store_true')
    parser.add_argument('-d', dest='debug', action='store_true')
    parser.add_argument('-p', dest='port', default=80, type=int)
    parser.add_argument('-k', dest='insecure', action='store_true')
    parser.add_argument('-t', dest='tests')
    parser.add_argument(dest="config")
    args = parser.parse_args()

    as_args, op_arg, config = main_setup(args, LOOKUP)

    _base = "{base}:{port}/".format(base=config.baseurl, port=args.port)

    INST = Instances(as_args, _base)

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        'session.auto': True,
        'session.key': "{}.beaker.session.id".format(
            urlparse(_base).netloc.replace(":", "."))
    }

    target = config.TARGET.format(quote_plus(_base))

    testspecs = parse_json_conf(args.tests,
                                cls_factories=[message.factory, client.factory],
                                chk_factories=[rp_check.factory],
                                func_factories=[])

    add_endpoints(ENDPOINTS)
    print(target)

    _dir = "./"
    LOOKUP = TemplateLookup(directories=[_dir + 'templates', _dir + 'htdocs'],
                            module_directory=_dir + 'modules',
                            input_encoding='utf-8',
                            output_encoding='utf-8')

    # Initiate the web server
    SRV = wsgiserver.CherryPyWSGIServer(
        ('0.0.0.0', int(args.port)),
        SessionMiddleware(application, session_opts, server_cls=Provider,
                          target=target, event_db=as_args['event_db'],
                          test_specs=testspecs, op_env={}, lookup=LOOKUP))

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
