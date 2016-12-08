import os

BASEDIR = os.path.abspath(os.path.dirname(__file__))

SERVER_CERT = "certs/cert.pem"
SERVER_KEY = "certs/key.pem"
CERT_CHAIN = None

# VERIFY_SSL = False

BASE = 'http://localhost'
ENT_PATH = 'entities'
ENT_INFO = 'entity_info'

# FLOWS = ['flows/flows_c.yaml']

KEYS = [
    {"key": "keys/enc.key", "type": "RSA", "use": ["enc"]},
    {"key": "keys/sig.key", "type": "RSA", "use": ["sig"]},
    {"crv": "P-256", "type": "EC", "use": ["sig"]},
    {"crv": "P-256", "type": "EC", "use": ["enc"]}
]
