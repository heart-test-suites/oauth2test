import os
import shutil
import filecmp
import datetime
import subprocess


def modification_date(filename):
    t = os.path.getmtime(filename)
    return datetime.datetime.fromtimestamp(t)


def copy_if_not_same(src, dst, overwrite=False):
    try:
        os.stat(dst)
    except OSError:
        shutil.copy(src, dst)
        return True

    if filecmp.cmp(src, dst):
        return False

    if modification_date(dst) > modification_date(src):
        if overwrite:
            shutil.copy(src, dst)
            return True

    return False


def oauth2_as_setup(distroot):
    for _dir in ['certs', 'keys', 'server_log', 'log', 'entities', 'jwks']:
        if os.path.isdir(_dir) is False:
            os.mkdir(_dir)

    _as_dir = os.path.join(distroot, 'test_tool', 'test_as')
    for _dir in ['static', 'mako', 'entity_info', "flows"]:
        _src = os.path.join(_as_dir, _dir)
        if os.path.isdir(_dir):
            shutil.rmtree(_dir)
        shutil.copytree(_src, _dir)

    for _fname in ['astest_run.sh','run.sh']:
        _file = os.path.join(_as_dir, _fname)
        copy_if_not_same(_file, _fname)

    for _fname in ['config_example.py', 'config_server.py',
                   'path2port.csv', 'tt_config_example.py']:
        _file = os.path.join(_as_dir, _fname)
        copy_if_not_same(_file, _fname, True)

    subprocess.call(
        ["make_entity_info.py", "-i", "https://example.com", "-p", "C.T.T.T",
         "-s", "-e", "-w", "diana@localhost:8040", "-t", "CTTT"])


def oauth2_rp_setup(distroot):
    for _dir in ['certs', 'keys', 'log']:
        if os.path.isdir(_dir) is False:
            os.mkdir(_dir)

    _op_dir = os.path.join(distroot, 'test_tool', 'test_rp')
    for _dir in ['static', 'htdocs', "flows"]:
        _src = os.path.join(_op_dir, _dir)
        if os.path.isdir(_dir):
            shutil.rmtree(_dir)
        shutil.copytree(_src, _dir)

    for _fname in ['example_conf.py', 'profiles.json',
                   'path2port.csv', 'uri-schemes-1.csv']:
        _file = os.path.join(_op_dir, _fname)
        copy_if_not_same(_file, _fname, True)

    for _fname in ['run.sh']:
        _file = os.path.join(_op_dir, _fname)
        copy_if_not_same(_file, _fname)
