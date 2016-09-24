# -*- coding: utf-8 -*-

from oic.extension.message import ServerMetadata
from oic.extension.provider import ClientInfoEndpoint
from oic.extension.provider import RevocationEndpoint
from oic.extension.provider import IntrospectionEndpoint

from oic.oauth2.provider import AuthorizationEndpoint
from oic.oauth2.provider import TokenEndpoint

from oic.oic.provider import RegistrationEndpoint

from otest.rp import check
from otest.rp import func
from otest.rp import operation

from otest.rp.endpoints import authorization
from otest.rp.endpoints import clientinfo
from otest.rp.endpoints import revocation
from otest.rp.endpoints import introspection
from otest.rp.endpoints import op_info
from otest.rp.endpoints import webfinger
from otest.rp.endpoints import css
from otest.rp.endpoints import registration
from otest.rp.endpoints import token
from otest.rp.parse_conf import parse_json_conf
from otest.rp.setup import main_setup

from oauth2test.rp.provider import Provider
#from oauth2test.rp.server import Server

BASE = "http://localhost"
baseurl = BASE
ISSUER = BASE

keys = [
    {"type": "RSA", "key": "keys/pyoidc_enc", "use": ["enc"]},
    {"type": "RSA", "key": "keys/pyoidc_sig", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["enc"]}
]

multi_keys = [
    {"type": "RSA", "use": ["enc"], "key": "keys/2nd_enc"},
    {"type": "RSA", "use": ["sig"], "key": "keys/2nd_sig"},
    {"type": "RSA", "use": ["enc"], "key": "keys/3rd_enc"},
    {"type": "RSA", "use": ["sig"], "key": "keys/3rd_sig"},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["enc"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["enc"]}
]

SERVICE_URL = "%s/verify" % ISSUER

AUTHENTICATION = {
    # Dummy authentication
    "NoAuthn": {"ACR": "PASSWORD", "WEIGHT": 1, "user": "diana"}
}

COOKIENAME = 'pyoic'
COOKIETTL = 4 * 60  # 4 hours
SYM_KEY = "SoLittleTime,Got"

#SERVER_CERT = "certs/server.crt"
#SERVER_KEY = "certs/server.key"
#CERT_CHAIN = None
#CA_BUNDLE = None

# =======  SIMPLE DATABASE ==============

USERINFO = "SIMPLE"

USERDB = {
    "diana": {
        "sub": "dikr0001",
        "name": "Diana Krall",
        "given_name": "Diana",
        "family_name": "Krall",
        "nickname": "Dina",
        "email": "diana@example.org",
        "email_verified": False,
        "phone_number": "+46 90 7865000",
        "address": {
            "street_address": "Umeå Universitet",
            "locality": "Umeå",
            "postal_code": "SE-90187",
            "country": "Sweden"
        },
    },
    "babs": {
        "sub": "babs0001",
        "name": "Barbara J Jensen",
        "given_name": "Barbara",
        "family_name": "Jensen",
        "nickname": "babs",
        "email": "babs@example.com",
        "email_verified": True,
        "address": {
            "street_address": "100 Universal City Plaza",
            "locality": "Hollywood",
            "region": "CA",
            "postal_code": "91608",
            "country": "USA",
        },
    },
    "upper": {
        "sub": "uppe0001",
        "name": "Upper Crust",
        "given_name": "Upper",
        "family_name": "Crust",
        "email": "uc@example.com",
        "email_verified": True,
    }
}

BEHAVIOR = {
    'client_registration': {
        'assign': {'token_endpoint_auth_method': 'private_key_jwt'}
    }
}


TOOL_ARGS = {
    'setup': main_setup,
    'check': check,
    'provider': Provider,
    'parse_conf': parse_json_conf,
    'cls_factories': {'': operation.factory},
    'chk_factory': check.factory,
    'func_factory': func.factory,
    'configuration_response': ServerMetadata,
    'endpoints': [
        AuthorizationEndpoint(authorization),
        TokenEndpoint(token),
        RegistrationEndpoint(registration),
        ClientInfoEndpoint(clientinfo),
        RevocationEndpoint(revocation),
        IntrospectionEndpoint(introspection)
    ],
    'urls': [
        (r'^.well-known/openid-configuration', op_info),
        (r'^.well-known/webfinger', webfinger),
        (r'.+\.css$', css),
    ],
    'profile_handler': None
    #'server_cls': Server
}

