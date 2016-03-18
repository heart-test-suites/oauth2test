# -*- coding: utf-8 -*-
from otest.parse_conf import parse_json_conf
from otest.setup import main_setup
from oauth2test.check import rp_check

from oic.extension.message import ServerMetadata
from oic.extension.provider import ClientInfoEndpoint
from oic.extension.provider import RevocationEndpoint
from oic.extension.provider import IntrospectionEndpoint
from oic.extension import message as exp_message

from oic.oauth2 import message
from oic.oauth2.provider import AuthorizationEndpoint
from oic.oauth2.provider import TokenEndpoint

from oic.oic.provider import RegistrationEndpoint

from otest.testtool import authorization
from otest.testtool import clientinfo
from otest.testtool import revocation
from otest.testtool import introspection
from otest.testtool import op_info
from otest.testtool import webfinger
from otest.testtool import css
from otest.testtool import registration
from otest.testtool import token

from oauth2test.provider import Provider

baseurl = "https://localhost"
issuer = "%s:%%d/" % baseurl

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

SERVICE_URL = "%s/verify" % issuer

AUTHENTICATION = {
    # Dummy authentication
    "NoAuthn": {"ACR": "PASSWORD", "WEIGHT": 1, "user": "diana"}
}

COOKIENAME = 'pyoic'
COOKIETTL = 4 * 60  # 4 hours
SYM_KEY = "SoLittleTime,Got"

SERVER_CERT = "certs/server.crt"
SERVER_KEY = "certs/server.key"
CERT_CHAIN = None
CA_BUNDLE = None

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

TARGET = 'https://localhost:8666/rp?issuer={}'

BEHAVIOR = {
    'client_registration': {
        'assign': {'token_endpoint_auth_method': 'private_key_jwt'}
    }
}


TOOL_ARGS = {
    'setup': main_setup,
    'check': rp_check,
    'provider': Provider,
    'parse_conf': parse_json_conf,
    'cls_factories': [message.factory, exp_message.factory],
    'chk_factories': [rp_check.factory],
    'func_factories': [],
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
    ]
}

