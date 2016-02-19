import json
import sys
import requests
from requests.packages import urllib3

__author__ = 'roland'

urllib3.disable_warnings()

resp = requests.request('GET', sys.argv[1], verify=False)

print(resp.status_code)
if resp.status_code == 200:
    info = json.loads(resp.text)

    print(json.dumps(info, sort_keys=True, indent=4, separators=(',', ': ')))
else:
    print(resp.text)