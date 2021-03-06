import os

BASEDIR = os.path.abspath(os.path.dirname(__file__))

SERVER_CERT = "certs/cert.pem"
SERVER_KEY = "certs/key.pem"
CERT_CHAIN = None

VERIFY_SSL = False

BASE_URL = 'http://localhost'
MAKO_DIR = 'mako'
ENT_PATH = 'entities'
ENT_INFO = 'entity_info'

FLOWDIR = 'flows'

PATH2PORT = 'path2port.csv'
PORT_MIN = 8100
PORT_MAX = 8149
