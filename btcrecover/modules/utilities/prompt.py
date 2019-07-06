from __future__ import print_function

import os
import sys

from btcrecover.modules.utilities.safe_print import error_exit


# Prompt user for a password (possibly containing Unicode characters)
def prompt_unicode_password(prompt, error_msg):
    program_name = os.path.basename(sys.argv[0])
    assert isinstance(prompt, str), "getpass() doesn't support Unicode on all platforms"
    from getpass import getpass
    encoding = sys.stdin.encoding or 'ASCII'
    if 'utf' not in encoding.lower():
        print(program_name + ": warning: terminal does not support UTF; passwords with non-ASCII chars might not work",
              file=sys.stderr)
    prompt = b"(note your password will not be displayed as you type)\n" + prompt
    password = getpass(prompt)
    if not password:
        error_exit(error_msg)
    if isinstance(password, str):
        password = password.decode(encoding)  # convert from terminal's encoding to unicode
    return password
