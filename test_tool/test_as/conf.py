__author__ = 'roland'

PORT = 8100
BASE = "http://localhost"

# If BASE is https these has to be specified
SERVER_CERT = "./certs/server.crt"
SERVER_KEY = "./certs/server.key"
CA_BUNDLE = None
VERIFY_SSL = False
CERT_CHAIN = None

ISSUER = "https://localhost:8092/"
#ISSUER = "https://oictest.umdc.umu.se:8051/"

KEY_EXPORT_URL = "%sstatic/jwk.json" % BASE

keys = [
    {
        "type": "RSA",
        "key": "./keys/rp_enc_key",
        "use": ["enc"],
    },
    {
        "type": "RSA",
        "key": "./keys/rp_sign_key",
        "use": ["sig"],
    },
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["enc"]}
]

REDIRECT_URIS_PATTERN = ["{}authz_cb"]

INFO = {
    "client": {
        #"redirect_uris": ["%sauthz_cb" % BASE],
        "application_type": "web",
        "contact": ["foo@example.com"]
    },
    'srv_discovery_url': ISSUER
    # registered
    # provider_info
}

TRUSTED_REGISTRATION_ENTITY = {
    'iss': 'https://has.example.com/tre',
    'jwks': 'tre.jwks',
}