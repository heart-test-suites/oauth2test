__author__ = 'roland'

PORT = 8088
BASE = "https://localhost:" + str(PORT) + "/"

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

INFO = {
    "client": {
        "redirect_uris": ["%sauthz_cb" % BASE],
        "application_type": "web",
        "contact": ["foo@example.com"]
    }
    # registered
    # srv_discovery_url
    # provider_info
}