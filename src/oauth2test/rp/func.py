import inspect
import sys

from future.backports.urllib.parse import urlencode


def set_configuration(oper, arg):
    oper.conv.entity.capabilities.update(arg)


def set_start_page(oper, args):
    _conf = oper.sh['test_conf']
    _url = _conf['start_page']
    _iss = oper.conv.entity.baseurl
    try:
        _params = _conf['params'].replace('<issuer>', _iss)
    except KeyError:
        oper.start_page = _url
    else:
        _args = dict([p.split('=') for p in _params.split('&')])
        oper.start_page = _url + '?' + urlencode(_args)


def set_op(oper, args):
    _op = oper.conv.entity
    for key, val in args.items():
        _attr = getattr(_op, key)
        if isinstance(_attr, dict):
            _attr.update(val)
        else:
            _attr = val


def factory(name):
    for fname, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isfunction(obj):
            if fname == name:
                return obj

    from otest.func import factory as ot_factory

    return ot_factory(name)
