#!/usr/bin/env python
import os
import sys
from oauth2test.site_setup import oauth2_as_setup
from oauth2test.site_setup import oauth2_rp_setup

DIR = {
    'oauth2_as': oauth2_as_setup,
    'oauth2_rp': oauth2_rp_setup,
}

if len(sys.argv) != 3:
    print('Usage: oidc_setup.py <root of oidctest src> <test site dir>')
    exit()

_distroot = {'oauth2': sys.argv[1]}
_root = sys.argv[2]
if os.path.isdir(_root) is False:
    os.makedirs(_root)

os.chdir(_root)
for _dir, func in DIR.items():
    if os.path.isdir(_dir) is False:
        os.mkdir(_dir)
    os.chdir(_dir)
    func(_distroot['oauth2'])
    os.chdir('..')
