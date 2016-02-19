#!/usr/bin/env python
import importlib
import json
import argparse
import six
import logging

from requests import ConnectionError
from mako.lookup import TemplateLookup
from future.backports.urllib.parse import parse_qs
from future.backports.urllib.parse import urlencode
from future.backports.urllib.parse import urlparse

from jwkest.jws import alg2keytype
from oic.utils.http_util import NotFound, get_post, ServiceError, BadRequest
from oic.utils.http_util import Response
from oic.utils.http_util import SeeOther

from requests.packages import urllib3

urllib3.disable_warnings()

LOGGER = logging.getLogger("")
LOGFILE_NAME = 'rp.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

CPC = ('%(asctime)s %(name)s:%(levelname)s '
       '[%(client)s,%(path)s,%(cid)s] %(message)s')
cpc_formatter = logging.Formatter(CPC)

hdlr.setFormatter(base_formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.DEBUG)

SERVER_ENV = {}


# noinspection PyUnresolvedReferences
def static(environ, start_response, logger, path):
    logger.info("[static]sending: %s" % (path,))

    try:
        text = open(path).read()
        if path.endswith(".ico"):
            start_response('200 OK', [('Content-Type', "image/x-icon")])
        elif path.endswith(".html"):
            start_response('200 OK', [('Content-Type', 'text/html')])
        elif path.endswith(".json"):
            start_response('200 OK', [('Content-Type', 'application/json')])
        elif path.endswith(".txt"):
            start_response('200 OK', [('Content-Type', 'text/plain')])
        elif path.endswith(".css"):
            start_response('200 OK', [('Content-Type', 'text/css')])
        else:
            start_response('200 OK', [('Content-Type', "text/xml")])
        return [text]
    except IOError:
        resp = NotFound()
        return resp(environ, start_response)


# def opresult_fragment(environ, start_response):
#     resp = Response(mako_template="opresult_repost.mako",
#                     template_lookup=LOOKUP,
#                     headers=[])
#     argv = {}
#     return resp(environ, start_response, **argv)
#
#
# def sorry_response(environ, start_response, homepage, err):
#     resp = Response(mako_template="sorry.mako",
#                     template_lookup=LOOKUP,
#                     headers=[])
#     argv = {"htmlpage": homepage,
#             "error": str(err)}
#     return resp(environ, start_response, **argv)


def get_id_token(client, session):
    return client.grant[session["state"]].get_id_token()


# Produce a JWS, a signed JWT, containing a previously received ID token
def id_token_as_signed_jwt(client, id_token, alg="RS256"):
    ckey = client.keyjar.get_signing_key(alg2keytype(alg), "")
    _signed_jwt = id_token.to_jwt(key=ckey, algorithm=alg)
    return _signed_jwt


def application(environ, start_response):
    session = environ['beaker.session']
    path = environ.get('PATH_INFO', '').lstrip('/')
    if path == "robots.txt":
        return static(environ, start_response, LOGGER, "static/robots.txt")

    if path.startswith("static/"):
        return static(environ, start_response, LOGGER, path)

    query = parse_qs(environ["QUERY_STRING"])
    acr_values = session._params['acrs']
    clients = session._params['clients']
    server_env = session._params['server_env']

    LOGGER.info(50 * "=")
    LOGGER.info("[{}] path: {}".format(session.id, path))
    LOGGER.info(50 * "=")

    if path == "rp":  # After having chosen which OP to authenticate at
        if "uid" in query:
            try:
                client = clients.dynamic_client(userid=query["uid"][0])
            except (ConnectionError, OIDCError) as err:
                res = ServiceError(err)
                return res(environ, start_response)
        elif 'issuer' in query:
            try:
                client = clients[query["issuer"][0]]
            except KeyError:
                try:
                    client = clients.dynamic_client(issuer=query["issuer"][0])
                except (ConnectionError, OIDCError) as err:
                    res = ServiceError(err)
                    return res(environ, start_response)
        else:
            client = clients[query["op"][0]]

        client.get_userinfo = False

        try:
            session['response_format'] = query["response_format"][0]
        except:
            session['response_format'] = 'html'

        session["op"] = client.provider_info["issuer"]

        try:
            resp = client.create_authn_request(session, acr_values)
        except Exception:
            raise
        else:
            return resp(environ, start_response)
    # elif path.endswith('authz_post'):
    #     try:
    #         _iss = session['op']
    #     except KeyError:
    #         LOGGER.info(
    #             '[{}] No active session with {}'.format(session.id,
    #                                                     environ[
    # 'REMOTE_ADDR']))
    #         return opchoice(environ, start_response, clients)
    #     else:
    #         client = clients[_iss]
    #
    #     query = parse_qs(get_post(environ))
    #     try:
    #         info = query["fragment"][0]
    #     except KeyError:
    #         return sorry_response(environ, start_response, conf.BASE,
    #                               "missing fragment ?!")
    #     if info == ['x']:
    #         return sorry_response(environ, start_response, conf.BASE,
    #                               "Expected fragment didn't get one ?!")
    #
    #     LOGGER.info('[{}] Fragment part: {}'.format(session.id, info))
    #
    #     try:
    #         result = client.callback(info, session, 'urlencoded')
    #         if isinstance(result, SeeOther):
    #             return result(environ, start_response)
    #     except OIDCError as err:
    #         return operror(environ, start_response, "%s" % err)
    #     except Exception as err:
    #         raise
    #     else:
    #         check_session_iframe_url = None
    #         try:
    #             check_session_iframe_url = client.provider_info[
    #                 "check_session_iframe"]
    #
    #             session["session_management"] = {
    #                 "session_state": query["session_state"][0],
    #                 "client_id": client.client_id,
    #                 "issuer": client.provider_info["issuer"]
    #             }
    #         except KeyError:
    #             pass
    #
    #         return opresult(environ, start_response, result['userinfo'],
    #                         result['user_id'], check_session_iframe_url)
    #
    elif path in clients.return_paths():  # After having authenticated at the OP
        try:
            _iss = session['op']
        except KeyError:
            txt = '[{}]No active session with {}'.format(
                session.id, environ['REMOTE_ADDR'])
            res = BadRequest(txt)
            return res(environ, start_response)

        # mismatch between callback and return_uri
        if _iss != clients.path[path]:
            txt = '[{}]issuer mismatch: {} != {}'.format(session.id, _iss,
                                                         clients.path[path])
            res = BadRequest(txt)
            return res(environ, start_response)

        client = clients[session["op"]]

        _response_type = client.behaviour["response_type"]
        try:
            _response_mode = client.authz_req[session['state']]['response_mode']
        except KeyError:
            _response_mode = ''

        LOGGER.info(
            "[{}]response_type: {}, response_mode: {}".format(session.id,
                                                              _response_type,
                                                              _response_mode))
        if _response_type and _response_type != "code":
            # Fall through if it's a query response anyway
            if query:
                pass
            elif _response_mode:
                # form_post encoded
                pass
            else:
                res = BadRequest('wrong response_type')
                return res(environ, start_response)

        LOGGER.info("[{}]Query part: {}".format(session.id, query))

        try:
            result = client.callback(query, session)
            if isinstance(result, SeeOther):
                return result(environ, start_response)
        except OIDCError as err:
            resp = ServiceError(err)
            return resp(environ, start_response)
        except Exception:
            raise
        else:
            check_session_iframe_url = None
            try:
                check_session_iframe_url = client.provider_info[
                    "check_session_iframe"]

                session["session_management"] = {
                    "session_state": query["session_state"][0],
                    "client_id": client.client_id,
                    "issuer": client.provider_info["issuer"]
                }
            except KeyError:
                pass

            result['id_token'] = result['id_token'].to_dict()
            res = Response(json.dumps(result))
            return res(environ, start_response)
    elif path == "logout":  # After the user has pressed the logout button
        try:
            _iss = session['op']
        except KeyError:
            txt = '[{}]No active session with {}'.format(session.id,
                                                         environ['REMOTE_ADDR'])
            resp = BadRequest(txt)
            return resp(environ, start_response, clients)
        client = clients[_iss]
        try:
            del client.authz_req[session['state']]
        except KeyError:
            pass

        logout_url = client.end_session_endpoint
        try:
            # Specify to which URL the OP should return the user after
            # log out. That URL must be registered with the OP at client
            # registration.
            logout_url += "?" + urlencode(
                {"post_logout_redirect_uri": client.registration_response[
                    "post_logout_redirect_uris"][0]})
        except KeyError:
            pass
        else:
            # If there is an ID token send it along as a id_token_hint
            _idtoken = get_id_token(client, session)
            if _idtoken:
                logout_url += "&" + urlencode({
                    "id_token_hint": id_token_as_signed_jwt(client, _idtoken,
                                                            "HS256")})
            # Also append the ACR values
            logout_url += "&" + urlencode({"acr_values": acr_values},
                                          True)

        LOGGER.debug("[{}]Logout URL: {}".format(session.id, logout_url))
        LOGGER.debug("Logging out from session: [{}]".format(session.id))
        session.delete()
        resp = SeeOther(str(logout_url))
        return resp(environ, start_response)
    elif path == "logout_success":  # post_logout_redirect_uri
        return Response("Logout successful!")(environ, start_response)

    resp = BadRequest('Unknown page')
    return resp(environ, start_response)


if __name__ == '__main__':
    from oic.utils.rp import OIDCClients
    from oic.utils.rp import OIDCError
    from beaker.middleware import SessionMiddleware
    from cherrypy import wsgiserver

    parser = argparse.ArgumentParser()
    parser.add_argument(dest="config")
    parser.add_argument("-p", default=8666, dest="port", help="port of the RP")
    parser.add_argument("-b", dest="base_url", help="base url of the RP")
    args = parser.parse_args()
    conf = importlib.import_module(args.config)

    if args.base_url:
        conf.BASE = args.base_url

    _base = "{base}:{port}/".format(base=conf.BASE, port=args.port)

    for _client, client_conf in six.iteritems(conf.CLIENTS):
        if "client_registration" in client_conf:
            client_reg = client_conf["client_registration"]
            client_reg["redirect_uris"] = [url.format(base=conf.BASE) for url in
                                           client_reg["redirect_uris"]]

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        'session.auto': True,
        'session.key': "{}.beaker.session.id".format(
            urlparse(conf.BASE).netloc.replace(":", "."))
    }

    _clients = OIDCClients(conf, _base)

    SRV = wsgiserver.CherryPyWSGIServer(
        ('0.0.0.0', int(args.port)),
        SessionMiddleware(application, session_opts,
                          clients=_clients, acrs=conf.ACR_VALUES,
                          server_env=SERVER_ENV))

    if conf.BASE.startswith("https"):
        from cherrypy.wsgiserver.ssl_builtin import BuiltinSSLAdapter

        SRV.ssl_adapter = BuiltinSSLAdapter(conf.SERVER_CERT, conf.SERVER_KEY,
                                            conf.CERT_CHAIN)
        extra = " using SSL/TLS"
    else:
        extra = ""

    txt = "RP server starting listening on port:%s%s" % (args.port, extra)
    LOGGER.info(txt)
    print(txt)

    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
