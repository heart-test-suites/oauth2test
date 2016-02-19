import json
import logging
import shelve
import importlib
import sys
from aatest.events import Events
from oic.extension.token import JWTToken

from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client
from oic.utils.authz import AuthzHandling
from oic.utils.keyio import keyjar_init
from oic.utils.sdb import SessionDB
from oic.utils.userinfo import UserInfo

from oidctest.provider import Provider
from oidctest.endpoints import add_endpoints
from oidctest.endpoints import ENDPOINTS

LOGGER = logging.getLogger(__name__)

__author__ = 'roland'


def main_setup(args, lookup):
    sys.path.insert(0, ".")
    config = importlib.import_module(args.config)
    config.issuer = config.issuer % args.port
    config.SERVICE_URL = config.SERVICE_URL % args.port

    # Client data base
    #cdb = shelve.open(config.CLIENT_DB, writeback=True)
    cdb = {}

    ac = AuthnBroker()

    for authkey, value in list(config.AUTHENTICATION.items()):
        authn = None
        # if "UserPassword" == authkey:
        #     from oic.utils.authn.user import UsernamePasswordMako
        #     authn = UsernamePasswordMako(None, "login.mako", LOOKUP, PASSWD,
        #                                  "authorization")

        if "NoAuthn" == authkey:
            from oic.utils.authn.user import NoAuthn

            authn = NoAuthn(None, user=config.AUTHENTICATION[authkey]["user"])

        if authn is not None:
            ac.add(config.AUTHENTICATION[authkey]["ACR"], authn,
                   config.AUTHENTICATION[authkey]["WEIGHT"])

    # dealing with authorization
    authz = AuthzHandling()

    kwargs = {
        "template_lookup": lookup,
        "template": {"form_post": "form_response.mako"},
    }

    if config.USERINFO == "SIMPLE":
        # User info is a simple dictionary in this case statically defined in
        # the configuration file
        userinfo = UserInfo(config.USERDB)
    else:
        userinfo = None

    # Should I care about verifying the certificates used by other entities
    if args.insecure:
        kwargs["verify_ssl"] = False
    else:
        kwargs["verify_ssl"] = True

    as_args = {
        "name": config.issuer,
        "cdb": cdb,
        "authn_broker": ac,
        "userinfo": userinfo,
        "authz": authz,
        "client_authn": verify_client,
        "symkey": config.SYM_KEY,
        "template_lookup": lookup,
        "template": {"form_post": "form_response.mako"},
        "jwks_name": "./static/jwks_{}.json",
        'event_db': Events()
    }

    com_args = {
        "name": config.issuer,
        # "sdb": SessionDB(config.baseurl),
        "baseurl": config.baseurl,
        "cdb": cdb,
        "authn_broker": ac,
        "userinfo": userinfo,
        "authz": authz,
        "client_authn": verify_client,
        "symkey": config.SYM_KEY,
        "template_lookup": lookup,
        "template": {"form_post": "form_response.mako"},
        "jwks_name": "./static/jwks_{}.json"
    }

    op_arg = {}

    try:
        op_arg["cookie_ttl"] = config.COOKIETTL
    except AttributeError:
        pass

    try:
        op_arg["cookie_name"] = config.COOKIENAME
    except AttributeError:
        pass

    # print URLS
    if args.debug:
        op_arg["debug"] = True

    # All endpoints the OpenID Connect Provider should answer on
    add_endpoints(ENDPOINTS)
    op_arg["endpoints"] = ENDPOINTS

    if args.port == 80:
        _baseurl = config.baseurl
    else:
        if config.baseurl.endswith("/"):
            config.baseurl = config.baseurl[:-1]
        _baseurl = "%s:%d" % (config.baseurl, args.port)

    if not _baseurl.endswith("/"):
        _baseurl += "/"

    op_arg["baseurl"] = _baseurl

    # Add own keys for signing/encrypting JWTs
    try:
        # a throw-away OP used to do the initial key setup
        _op = Provider(sdb=SessionDB(com_args["baseurl"]), **com_args)
        jwks = keyjar_init(_op, config.keys)
    except KeyError:
        pass
    else:
        op_arg["jwks"] = jwks
        op_arg["keys"] = config.keys

        as_args['jwks_uri'] = '{}{}/jwks.json'.format(_baseurl, 'static')
        as_args['jwks_name'] = 'static/jwks.json'

        f = open('static/jwks.json', 'w')
        f.write(json.dumps(jwks))
        f.close()

        as_args['keyjar'] = _op.keyjar
        as_args['sdb'] = SessionDB(
            com_args["baseurl"],
            token_factory=JWTToken('T', keyjar=_op.keyjar,
                                   lifetime={'code': 3600, 'token': 900},
                                   iss=_baseurl,
                                   sign_alg='RS256'),
            refresh_token_factory=JWTToken(
                'R', keyjar=_op.keyjar, lifetime={'': 24 * 3600},
                iss=_baseurl)
        )

    try:
        op_arg["marg"] = multi_keys(as_args, config.multi_keys)
    except AttributeError as err:
        pass

    return as_args, op_arg, config


def multi_keys(as_args, key_conf):
    # a throw-away OP used to do the initial key setup
    _op = Provider(**as_args)
    jwks = keyjar_init(_op, key_conf, "m%d")

    return {"jwks": jwks, "keys": key_conf}
