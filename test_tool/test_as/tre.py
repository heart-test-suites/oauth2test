import json
from oic.utils.keyio import build_keyjar, dump_jwks

__author__ = 'roland'

key_conf = [
    {"type": "RSA", "name": "tre", "use": ["enc", "sig"]},
]

pub_jwks, keyjar, kdd = build_keyjar(key_conf, "tre%d", None, None)

# To get the private keys
priv_jwks = keyjar.export_jwks(private=True)

f = open('tre.jwks', 'w')
f.write(json.dumps(priv_jwks))
f.close()