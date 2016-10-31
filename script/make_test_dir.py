#!/usr/bin/env python

import sys
import os
import shutil

_distroot = sys.argv[1]
_root = sys.argv[2]
os.makedirs(_root)

os.chdir(_root)
for _dir in ['certs', 'keys', 'server_log', 'log']:
    os.mkdir(_dir)

_op_dir = os.path.join(_distroot, 'test_tool', 'test_as')
for _dir in ['static', 'htdocs']:
    _src = os.path.join(_op_dir, _dir)
    shutil.copytree(_src, _dir)

for _fname in ['flows.yaml', 'start.sh', 'sslconf.py']:
    _file = os.path.join(_op_dir, _fname)
    shutil.copy(_file, '.')
