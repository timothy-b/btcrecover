from __future__ import print_function
import os, sys

prog = os.path.basename(sys.argv[0])

# Replace the builtin print with one which won't die when attempts are made to print
# unicode strings which contain characters unsupported by the destination console
#
builtin_print = print


def safe_print(*args, **kwargs):
    if kwargs.get("file") in (None, sys.stdout, sys.stderr):
        builtin_print(*_do_safe_print(*args, **kwargs), **kwargs)
    else:
        builtin_print(*args, **kwargs)


def _do_safe_print(*args, **kwargs):
    try:
        encoding = kwargs.get("file", sys.stdout).encoding or "ascii"
    except AttributeError:
        encoding = "ascii"
    converted_args = []
    for arg in args:
        if isinstance(arg, unicode):
            arg = arg.encode(encoding, errors="replace")
        converted_args.append(arg)
    return converted_args


# noinspection PyShadowingBuiltins
print = safe_print


# Calls sys.exit with an error message, taking unnamed arguments as print() does
def error_exit(*messages):
    sys.exit(b" ".join(map(str, _do_safe_print(prog+": error:", *messages))))