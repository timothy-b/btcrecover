# btcrpass.py -- btcrecover main library
# Copyright (C) 2014-2017 Christopher Gurnee
#
# This file is part of btcrecover.
#
# btcrecover is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.
#
# btcrecover is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/

# If you find this program helpful, please consider a small
# donation to the developer at the following Bitcoin address:
#
#           3Au8ZodNHPei7MQiSVAWb7NB2yqsb48GW4
#
#                      Thank You!

# TODO: put everything in a class?
# TODO: pythonize comments/documentation

# (all optional futures for 2.7)
from __future__ import print_function, absolute_import, division, unicode_literals

import argparse
import atexit
import cPickle
import gc
import hashlib
import itertools
import multiprocessing
import numbers
import os
import re
import signal
import sys
import time
import timeit

# all of the "unused" modules are used in testing :)
# the commented out ones have circular dependencies on btrseed
import btcrecover.btrcpass.configurables as config
import btcrecover.btrcpass.mode as mode
from btcrecover.btrcpass.wallets.android_spending_pin import WalletAndroidSpendingPIN
from btcrecover.btrcpass.wallets.armory import WalletArmory
#from btcrecover.btrcpass.wallets.bip_39 import WalletBIP39
from btcrecover.btrcpass.wallets.bitcoin_core import WalletBitcoinCore
from btcrecover.btrcpass.wallets.bitcoinj import WalletBitcoinj
#from btcrecover.btrcpass.wallets.bither import WalletBither
from btcrecover.btrcpass.wallets.blockchain import WalletBlockchain
from btcrecover.btrcpass.wallets.blockchain_secondpass import WalletBlockchainSecondpass
from btcrecover.btrcpass.wallets.electrum1 import WalletElectrum1
from btcrecover.btrcpass.wallets.electrum2 import WalletElectrum2
from btcrecover.btrcpass.wallets.electrum_loose_key import WalletElectrumLooseKey
from btcrecover.btrcpass.wallets.msigna import WalletMsigna
from btcrecover.btrcpass.wallets.multibit import WalletMultiBit
#from btcrecover.btrcpass.wallets.multibit_hd import WalletMultiBitHD
from btcrecover.btrcpass.wallets.null import WalletNull
from btcrecover.btrcpass.wallets.pywallet import WalletPywallet
from btcrecover.btrcpass.wallets.wallet import Wallet

# The progressbar module is recommended but optional; it is typically
# distributed with btcrecover (it is loaded later on demand)

__version__          = "0.17.10"
__ordering_version__ = b"0.6.4"  # must be updated whenever password ordering changes


def full_version():
    from struct import calcsize
    return "btcrecover {} on Python {} {}-bit, {}-bit unicodes, {}-bit ints".format(
        __version__,
        ".".join(str(i) for i in sys.version_info[:3]),
        calcsize(b"P") * 8,
        sys.maxunicode.bit_length(),
        sys.maxint.bit_length() + 1
    )


enable_ascii_mode = mode.enable_ascii_mode
enable_unicode_mode = mode.enable_unicode_mode


# Load the OpenCL libraries and return a list of available devices
cl_devices_avail = None
def get_opencl_devices():
    global pyopencl, numpy, cl_devices_avail
    if cl_devices_avail is None:
        try:
            import pyopencl
            import numpy
            cl_devices_avail = filter(lambda d: d.available == 1
                                        and d.profile == "FULL_PROFILE"
                                        and d.endian_little == 1,
                                      itertools.chain(*[p.get_devices() for p in pyopencl.get_platforms()]))
        except ImportError as e:
            print(prog+": warning:", e, file=sys.stderr)
            cl_devices_avail = []
        except pyopencl.LogicError as e:
            if "platform not found" not in unicode(e):
                raise  # unexpected error
            cl_devices_avail = []  # PyOpenCL loaded OK but didn't find any supported hardware
    return cl_devices_avail


################################### Argument Parsing ###################################


# Replace the builtin print with one which won't die when attempts are made to print
# unicode strings which contain characters unsupported by the destination console
#
builtin_print = print
#
def safe_print(*args, **kwargs):
    if kwargs.get("file") in (None, sys.stdout, sys.stderr):
        builtin_print(*_do_safe_print(*args, **kwargs), **kwargs)
    else:
        builtin_print(*args, **kwargs)
#
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
#
print = safe_print

# Calls sys.exit with an error message, taking unnamed arguments as print() does
def error_exit(*messages):
    sys.exit(b" ".join(map(str, _do_safe_print(prog+": error:", *messages))))

# Ensures all chars in the string fall inside the acceptable range for the current mode
def check_chars_range(s, error_msg, no_replacement_chars=False):
    assert isinstance(s, mode.tstr), "check_chars_range: s is of " + unicode(mode.tstr)
    if mode.tstr == str:
        # For ASCII mode, checks that the input string's chars are all 7-bit US-ASCII
        for c in s:
            if ord(c) > 127:  # 2**7 - 1
                error_exit(error_msg, "has character with code point", ord(c), "> max (127 / ASCII)\n"
                                      "(see the Unicode Support section in the Tutorial and the --utf8 option)")
    else:
        # For Unicode mode, a REPLACEMENT CHARACTER indicates a failed conversion from UTF-8
        if no_replacement_chars and "\uFFFD" in s:
            error_exit(error_msg, "contains an invalid UTF-8 byte sequence")
        # For UTF-16 (a.k.a. "narrow" Python Unicode) builds, checks that the input unicode
        # string has no surrogate pairs (all chars fit inside one UTF-16 code unit)
        if sys.maxunicode < 65536:  # 2**16
            for c in s:
                c = ord(c)
                if 0xD800 <= c <= 0xDBFF or 0xDC00 <= c <= 0xDFFF:
                    error_exit(error_msg, "has character with code point > max ("+unicode(sys.maxunicode)+" / Unicode BMP)")


# Returns an (order preserved) list or string with duplicate elements removed
# (if input is a string, returns a string, otherwise returns a list)
# (N.B. not a generator function, so faster for small inputs, not for large)
def duplicates_removed(iterable):
    if args.no_dupchecks >= 4:
        if isinstance(iterable, basestring) or isinstance(iterable, list):
            return iterable
        return list(iterable)
    seen = set()
    unique = []
    for x in iterable:
        if x not in seen:
            unique.append(x)
            seen.add(x)
    if len(unique) == len(iterable) and (isinstance(iterable, basestring) or isinstance(iterable, list)):
        return iterable
    elif isinstance(iterable, basestring):
        return type(iterable)().join(unique)
    return unique

# Converts a wildcard set into a string, expanding ranges and removing duplicates,
# e.g.: "hexa-fA-F" -> "hexabcdfABCDEF"
def build_wildcard_set(set_string):
    return duplicates_removed(re.sub(br"(.)-(.)", expand_single_range, set_string))
#
def expand_single_range(m):
    char_first, char_last = map(ord, m.groups())
    if char_first > char_last:
        raise ValueError("first character in wildcard range '"+unichr(char_first)+"' > last '"+unichr(char_last)+"'")
    return mode.tstr().join(map(mode.tchr, xrange(char_first, char_last + 1)))

# Returns an integer count of valid wildcards in the string, or
# a string error message if any invalid wildcards are present
# (see expand_wildcards_generator() for more details on wildcards)
def count_valid_wildcards(str_with_wildcards, permit_contracting_wildcards = False):
    # Remove all valid wildcards, syntax checking the min to max ranges; if any %'s are left they are invalid
    try:
        valid_wildcards_removed, count = \
            re.subn(br"%(?:(?:(\d+),)?(\d+))?(?:i?[{}]|i?\[.+?\]{}|(?:;.+?;(\d+)?|;(\d+))?b)"
                    .format(config.wildcard_keys, b"|[<>-]" if permit_contracting_wildcards else b""),
                    syntax_check_range, str_with_wildcards)
    except ValueError as e: return unicode(e)
    if mode.tstr("%") in valid_wildcards_removed:
        invalid_wildcard_msg = "invalid wildcard (%) syntax (use %% to escape a %)"
        # If checking with permit_contracting_wildcards==True returns something different,
        # then the string must contain contracting wildcards (which were not permitted)
        if not permit_contracting_wildcards and \
                count_valid_wildcards(str_with_wildcards, True) != invalid_wildcard_msg:
            return "contracting wildcards are not permitted here"
        else:
            return invalid_wildcard_msg
    if count == 0: return 0
    # Expand any custom wildcard sets for the sole purpose of checking for exceptions (e.g. %[z-a])
    # We know all wildcards present have valid syntax, so we don't need to use the full regex, but
    # we do need to capture %% to avoid parsing this as a wildcard set (it isn't one): %%[not-a-set]
    for wildcard_set in re.findall(br"%[\d,i]*\[(.+?)\]|%%", str_with_wildcards):
        if wildcard_set:
            try:   re.sub(br"(.)-(.)", expand_single_range, wildcard_set)
            except ValueError as e: return mode.tstr(e)
    return count
#
def syntax_check_range(m):
    minlen, maxlen, bpos, bpos2 = m.groups()
    if minlen and maxlen and int(minlen) > int(maxlen):
        raise ValueError("max wildcard length ("+maxlen+") must be >= min length ("+minlen+")")
    if maxlen and int(maxlen) == 0:
        print(prog+": warning: %0 or %0,0 wildcards always expand to empty strings", file=sys.stderr)
    if bpos2: bpos = bpos2  # at most one of these is not None
    if bpos and int(bpos) == 0:
        raise ValueError("backreference wildcard position must be > 0")
    return mode.tstr("")


# Loads the savestate from the more recent save slot in an autosave_file (into a global)
SAVESLOT_SIZE = 4096
def load_savestate(autosave_file):
    global savestate, autosave_nextslot
    savestate0 = savestate1 = first_error = None
    # Try to load both save slots, ignoring pickle errors at first
    autosave_file.seek(0)
    try:
        savestate0 = cPickle.load(autosave_file)
    except Exception as e:
        first_error = e
    else:  assert autosave_file.tell() <= SAVESLOT_SIZE, "load_savestate: slot 0 data <= "+unicode(SAVESLOT_SIZE)+" bytes long"
    autosave_file.seek(0, os.SEEK_END)
    autosave_len = autosave_file.tell()
    if autosave_len > SAVESLOT_SIZE:  # if the second save slot is present
        autosave_file.seek(SAVESLOT_SIZE)
        try:
            savestate1 = cPickle.load(autosave_file)
        except Exception: pass
        else:  assert autosave_file.tell() <= 2*SAVESLOT_SIZE, "load_savestate: slot 1 data <= "+unicode(SAVESLOT_SIZE)+" bytes long"
    else:
        # Convert an old format file to a new one by making it at least SAVESLOT_SIZE bytes long
        autosave_file.write((SAVESLOT_SIZE - autosave_len) * b"\0")
    #
    # Determine which slot is more recent, and use it
    if savestate0 and savestate1:
        use_slot = 0 if savestate0[b"skip"] >= savestate1[b"skip"] else 1
    elif savestate0:
        if autosave_len > SAVESLOT_SIZE:
            print(prog+": warning: data in second autosave slot was corrupted, using first slot", file=sys.stderr)
        use_slot = 0
    elif savestate1:
        print(prog+": warning: data in first autosave slot was corrupted, using second slot", file=sys.stderr)
        use_slot = 1
    else:
        print(prog+": warning: data in both primary and backup autosave slots is corrupted", file=sys.stderr)
        raise first_error
    if use_slot == 0:
        savestate = savestate0
        autosave_nextslot =  1
    else:
        assert use_slot == 1
        savestate = savestate1
        autosave_nextslot =  0


# Converts a file-like object into a new file-like object with an added peek() method, e.g.:
#   file = open(filename)
#   peekable_file = MakePeekable(file)
#   next_char = peekable_file.peek()
#   assert next_char == peekable_file.read(1)
# Do not take references of the member functions, e.g. don't do this:
#   tell_ref = peekable_file.tell
#   print peekable_file.peek()
#   location = tell_ref(peekable_file)       # will be off by one;
#   assert location == peekable_file.tell()  # will assert
class MakePeekable(object):
    def __new__(cls, file):
        if isinstance(file, MakePeekable):
            return file
        else:
            self         = object.__new__(cls)
            self._file   = file
            self._peeked = b""
            return self
    #
    def peek(self):
        if not self._peeked:
            if hasattr(self._file, "peek"):
                real_peeked = self._file.peek(1)
                if len(real_peeked) >= 1:
                    return real_peeked[0]
            self._peeked = self._file.read(1)
        return self._peeked
    #
    def read(self, size = -1):
        if size == 0: return mode.tstr("")
        peeked = self._peeked
        self._peeked = b""
        return peeked + self._file.read(size - 1) if peeked else self._file.read(size)
    def readline(self, size = -1):
        if size == 0: return mode.tstr("")
        peeked = self._peeked
        self._peeked = b""
        if peeked == b"\n": return peeked # A blank Unix-style line (or OS X)
        if peeked == b"\r":               # A blank Windows or MacOS line
            if size == 1:
                return peeked
            if self.peek() == b"\n":
                peeked = self._peeked
                self._peeked = b""
                return b"\r"+peeked       # A blank Windows-style line
            return peeked                 # A blank MacOS-style line (not OS X)
        return peeked + self._file.readline(size - 1) if peeked else self._file.readline(size)
    def readlines(self, size = -1):
        lines = []
        while self._peeked:
            lines.append(self.readline())
        return lines + self._file.readlines(size)  # (this size is just a hint)
    #
    def __iter__(self):
        return self
    def next(self):
        return self.readline() if self._peeked else self._file.next()
    #
    reset_before_calling = {"seek", "tell", "truncate", "write", "writelines"}
    def __getattr__(self, name):
        if self._peeked and name in MakePeekable.reset_before_calling:
            self._file.seek(-1, os.SEEK_CUR)
            self._peeked = b""
        return getattr(self._file, name)
    #
    def close(self):
        self._peeked = b""
        self._file.close()


# Opens a new or returns an already-opened file, if it passes the specified constraints.
# * Only examines one file: if filename == "__funccall" and funccall_file is not None,
#   use it. Otherwise if filename is not None, use it. Otherwise if default_filename
#   exists, use it (possibly with its extension duplicated). Otherwise, return None.
# * After deciding which one file to potentially use, check it against the require_data
#   or new_or_empty "no-exception" constraints and just return None if either fails.
#   (These are "soft" fails which don't raise exceptions.)
# * Tries to open (if not already opened) and return the file, letting any exception
#   raised by open (a "hard" fail) to pass up.
# * For Unicode builds (when mode.tstr == unicode), returns an mode.io.TextIOBase which produces
#   unicode strings if and only if filemode is text (is not binary / does not contain "b").
# * The results of opening stdin more than once are undefined.
def open_or_use(filename, filemode = "r",
        funccall_file    = None,   # already-opened file used if filename == "__funccall"
        permit_stdin     = None,   # when True a filename == "-" opens stdin
        default_filename = None,   # name of file that can be opened if filename == None
        require_data     = None,   # open if file is non-empty, else return None
        new_or_empty     = None,   # open if file is new or empty, else return None
        make_peekable    = None,   # the returned file object is given a peek method
        decoding_errors  = None):  # the Unicode codec error mode (default: strict)
    assert not(permit_stdin and require_data), "open_or_use: stdin cannot require_data"
    assert not(permit_stdin and new_or_empty), "open_or_use: stdin is never new_or_empty"
    assert not(require_data and new_or_empty), "open_or_use: can either require_data or be new_or_empty"
    #
    # If the already-opened file was requested
    if funccall_file and filename == "__funccall":
        if require_data or new_or_empty:
            funccall_file.seek(0, os.SEEK_END)
            if funccall_file.tell() == 0:
                # The file is empty; if it shouldn't be:
                if require_data: return None
            else:
                funccall_file.seek(0)
                # The file has contents; if it shouldn't:
                if new_or_empty: return None
        if mode.tstr == unicode:
            if "b" in filemode:
                assert not isinstance(funccall_file, mode.io.TextIOBase), "already opened file not an mode.io.TextIOBase; produces bytes"
            else:
                assert isinstance(funccall_file, mode.io.TextIOBase), "already opened file isa mode.io.TextIOBase producing unicode"
        return MakePeekable(funccall_file) if make_peekable else funccall_file;
    #
    if permit_stdin and filename == "-":
        if mode.tstr == unicode and "b" not in filemode:
            sys.stdin = mode.io.open(sys.stdin.fileno(), filemode,
                                     encoding= sys.stdin.encoding or "utf_8_sig", errors= decoding_errors)
        if make_peekable:
            sys.stdin = MakePeekable(sys.stdin)
        return sys.stdin
    #
    # If there was no file specified, but a default exists
    if not filename and default_filename:
        if permit_stdin and default_filename == "-":
            if mode.tstr == unicode and "b" not in filemode:
                sys.stdin = mode.io.open(sys.stdin.fileno(), filemode,
                                         encoding= sys.stdin.encoding or "utf_8_sig", errors= decoding_errors)
            if make_peekable:
                sys.stdin = MakePeekable(sys.stdin)
            return sys.stdin
        if os.path.isfile(default_filename):
            filename = default_filename
        else:
            # For default filenames only, try doubling the extension to help users who don't realize
            # their shell is hiding the extension (and thus the actual file has "two" extensions)
            default_filename, default_ext = os.path.splitext(default_filename)
            default_filename += default_ext + default_ext
            if os.path.isfile(default_filename):
                filename = default_filename
    if not filename:
        return None
    #
    filename = mode.tstr_from_stdin(filename)
    if require_data and (not os.path.isfile(filename) or os.path.getsize(filename) == 0):
        return None
    if new_or_empty and os.path.exists(filename) and (os.path.getsize(filename) > 0 or not os.path.isfile(filename)):
        return None
    #
    if mode.tstr == unicode and "b" not in filemode:
        file = mode.io.open(filename, filemode, encoding="utf_8_sig", errors=decoding_errors)
    else:
        file = open(filename, filemode)
    #
    if "b" not in filemode:
        if file.read(5) == br"{\rtf":
            error_exit(filename, "must be a plain text file (.txt), not a Rich Text File (.rtf)")
        file.seek(0)
    #
    return MakePeekable(file) if make_peekable else file


# Enables pause-before-exit (at most once per program run) if stdin is interactive (a tty)
pause_registered = None
def enable_pause():
    global pause_registered
    if pause_registered is None:
        if sys.stdin.isatty():
            atexit.register(lambda: not multiprocessing.current_process().name.startswith("PoolWorker-") and
                                    raw_input("Press Enter to exit ..."))
            pause_registered = True
        else:
            print(prog+": warning: ignoring --pause since stdin is not interactive (or was redirected)", file=sys.stderr)
            pause_registered = False


ADDRESSDB_DEF_FILENAME = "addresses.db"  # copied from btrseed

# can raise an exception on some platforms
try:
    cpus = multiprocessing.cpu_count()
except StandardError:
    cpus = 1

parser_common = argparse.ArgumentParser(add_help=False)
prog = unicode(parser_common.prog)
parser_common_initialized = False


def init_parser_common():
    global parser_common, parser_common_initialized, typo_types_group, bip39_group
    if not parser_common_initialized:
        # Build the list of command-line options common to both tokenlist and passwordlist files
        parser_common.add_argument("--wallet",      metavar="FILE", help="the wallet file (this, --data-extract, or --listpass is required)")
        parser_common.add_argument("--typos",       type=int, metavar="COUNT", help="simulate up to this many typos; you must choose one or more typo types from the list below")
        parser_common.add_argument("--min-typos",   type=int, default=0, metavar="COUNT", help="enforce a min # of typos included per guess")
        typo_types_group = parser_common.add_argument_group("typo types")
        typo_types_group.add_argument("--typos-capslock", action="store_true", help="try the password with caps lock turned on")
        typo_types_group.add_argument("--typos-swap",     action="store_true", help="swap two adjacent characters")
        for typo_name, typo_args in config.simple_typo_args.items():
            typo_types_group.add_argument("--typos-"+typo_name, **typo_args)
        typo_types_group.add_argument("--typos-insert",   metavar="WILDCARD-STRING", help="insert a string or wildcard")
        for typo_name in itertools.chain(("swap",), config.simple_typo_args.keys(), ("insert",)):
            typo_types_group.add_argument("--max-typos-"+typo_name, type=int, default=sys.maxint, metavar="#", help="limit the number of --typos-"+typo_name+" typos")
        typo_types_group.add_argument("--max-adjacent-inserts", type=int, default=1, metavar="#", help="max # of --typos-insert strings that can be inserted between a single pair of characters (default: %(default)s)")
        parser_common.add_argument("--custom-wild", metavar="STRING",    help="a custom set of characters for the %%c wildcard")
        parser_common.add_argument("--utf8",        action="store_true", help="enable Unicode mode; all input must be in UTF-8 format")
        parser_common.add_argument("--regex-only",  metavar="STRING",    help="only try passwords which match the given regular expr")
        parser_common.add_argument("--regex-never", metavar="STRING",    help="never try passwords which match the given regular expr")
        parser_common.add_argument("--delimiter",   metavar="STRING",    help="the delimiter between tokens in the tokenlist or columns in the typos-map (default: whitespace)")
        parser_common.add_argument("--skip",        type=int, default=0,    metavar="COUNT", help="skip this many initial passwords for continuing an interrupted search")
        parser_common.add_argument("--threads",     type=int, default=cpus, metavar="COUNT", help="number of worker threads (default: number of CPUs, %(default)s)")
        parser_common.add_argument("--worker",      metavar="ID#/TOTAL#",   help="divide the workload between TOTAL# servers, where each has a different ID# between 1 and TOTAL#")
        parser_common.add_argument("--max-eta",     type=int, default=168,  metavar="HOURS", help="max estimated runtime before refusing to even start (default: %(default)s hours, i.e. 1 week)")
        parser_common.add_argument("--no-eta",      action="store_true",    help="disable calculating the estimated time to completion")
        parser_common.add_argument("--est-passwords", type=int, default=0, metavar="COUNT", help="number of passwords you estimate your input to contain. used to display progress if --no-eta is enabled")
        parser_common.add_argument("--no-dupchecks", "-d", action="count", default=0, help="disable duplicate guess checking to save memory; specify up to four times for additional effect")
        parser_common.add_argument("--no-progress", action="store_true",   default=not sys.stdout.isatty(), help="disable the progress bar")
        parser_common.add_argument("--android-pin", action="store_true", help="search for the spending pin instead of the backup password in a Bitcoin Wallet for Android/BlackBerry")
        parser_common.add_argument("--blockchain-secondpass", action="store_true", help="search for the second password instead of the main password in a Blockchain wallet")
        parser_common.add_argument("--msigna-keychain", metavar="NAME",  help="keychain whose password to search for in an mSIGNA vault")
        parser_common.add_argument("--data-extract",action="store_true", help="prompt for data extracted by one of the extract-* scripts instead of using a wallet file")
        parser_common.add_argument("--mkey",        action="store_true", help=argparse.SUPPRESS)  # deprecated, use --data-extract instead
        parser_common.add_argument("--privkey",     action="store_true", help=argparse.SUPPRESS)  # deprecated, use --data-extract instead
        parser_common.add_argument("--exclude-passwordlist", metavar="FILE", nargs="?", const="-", help="never try passwords read (exactly one per line) from this file or from stdin")
        parser_common.add_argument("--listpass",    action="store_true", help="just list all password combinations to test and exit")
        parser_common.add_argument("--performance", action="store_true", help="run a continuous performance test (Ctrl-C to exit)")
        parser_common.add_argument("--pause",       action="store_true", help="pause before exiting")
        parser_common.add_argument("--version","-v",action="store_true", help="show full version information and exit")
        bip39_group = parser_common.add_argument_group("BIP-39 passwords")
        bip39_group.add_argument("--bip39",      action="store_true",   help="search for a BIP-39 password instead of from a wallet")
        bip39_group.add_argument("--mpk",        metavar="XPUB",        help="the master public key")
        bip39_group.add_argument("--addrs",      metavar="ADDRESS", nargs="+", help="if not using an mpk, address(es) in the wallet")
        bip39_group.add_argument("--addressdb",  metavar="FILE",    nargs="?", help="if not using addrs, use a full address database (default: %(const)s)", const=ADDRESSDB_DEF_FILENAME)
        bip39_group.add_argument("--addr-limit", type=int, metavar="COUNT",    help="if using addrs or addressdb, the generation limit")
        bip39_group.add_argument("--language",   metavar="LANG-CODE",   help="the wordlist language to use (see wordlists/README.md, default: auto)")
        bip39_group.add_argument("--bip32-path", metavar="PATH",        help="path (e.g. m/0'/0/) excluding the final index (default: BIP-44 account 0)")
        bip39_group.add_argument("--mnemonic-prompt", action="store_true", help="prompt for the mnemonic guess via the terminal (default: via the GUI)")
        bip39_group.add_argument("--wallet-type",     metavar="TYPE",      help="the wallet type, e.g. ethereum (default: bitcoin)")
        gpu_group = parser_common.add_argument_group("GPU acceleration")
        gpu_group.add_argument("--enable-gpu", action="store_true",     help="enable experimental OpenCL-based GPU acceleration (only supports Bitcoin Core wallets and extracts)")
        gpu_group.add_argument("--global-ws",  type=int, nargs="+",     default=[4096], metavar="PASSWORD-COUNT", help="OpenCL global work size (default: 4096)")
        gpu_group.add_argument("--local-ws",   type=int, nargs="+",     default=[None], metavar="PASSWORD-COUNT", help="OpenCL local work size; --global-ws must be evenly divisible by --local-ws (default: auto)")
        gpu_group.add_argument("--mem-factor", type=int,                default=1,      metavar="FACTOR", help="enable memory-saving space-time tradeoff for Armory")
        gpu_group.add_argument("--calc-memory",action="store_true",     help="list the memory requirements for an Armory wallet")
        gpu_group.add_argument("--gpu-names",  nargs="+",               metavar="NAME-OR-ID", help="choose GPU(s) on multi-GPU systems (default: auto)")
        gpu_group.add_argument("--list-gpus",  action="store_true",     help="list available GPU names and IDs, then exit")
        gpu_group.add_argument("--int-rate",   type=int, default=200,   metavar="RATE", help="interrupt rate: raise to improve PC's responsiveness at the expense of search performance (default: %(default)s)")
        parser_common_initialized = True

# A decorator that can be used to register a custom simple typo generator function
# so that it may be passed to parse_arguments() as an option like any other
def register_simple_typo(name, help = None):
    assert name.isalpha() and name.islower(), "simple typo name must have only lowercase letters"
    assert name not in config.simple_typos,          "simple typo must not already exist"
    init_parser_common()  # ensure typo_types_group has been initialized
    arg_params = dict(action="store_true")
    if help:
        args["help"] = help
    typo_types_group.add_argument("--typos-"+name, **arg_params)
    typo_types_group.add_argument("--max-typos-"+name, type=int, default=sys.maxint, metavar="#", help="limit the number of --typos-"+name+" typos")
    def decorator(simple_typo_generator):
        config.simple_typos[name] = simple_typo_generator
        return simple_typo_generator  # the decorator returns it unmodified, it just gets registered
    return decorator


# Once parse_arguments() has completed, password_generator_factory() will return an iterator
# (actually a generator object) configured to generate all the passwords requested by the
# command-line options, and loaded_wallet.return_verified_password_or_false() can check
# passwords against the wallet or key that was specified. (Typically called with sys.argv[1:]
# as its only parameter followed by a call to main() to perform the actual password search.)
#
# wallet         - a custom wallet object which must implement
#                  return_verified_password_or_false() and which should be pickleable
#                  (instead of specifying a --wallet or --data-extract)
# base_iterator  - either an iterable or a generator function which produces the base
#                  (without typos) passwords to be checked; unless --no-eta is specified,
#                  it must be possible to iterate over all the passwords more than once
#                  (instead of specifying a --tokenlist or --passwordlist)
# perf_iterator  - a generator function which produces an infinite stream of unique
#                  passwords which is used iff a --performance test is specified
#                  (if omitted, the default perf iterator which generates strings is used)
# inserted_items - instead of specifying "--typos-insert items-to-insert", this can be
#                  an iterable of the items to insert (useful if the wildcard language
#                  is not flexible enough or if the items to insert are not strings)
# check_only     - (similar in concept to --regex-only) a boolean function accepting an
#                  item just before it is passed to return_verified_password_or_false()
#                  which should return False if the the item should not be checked.
#
# TODO: document kwds usage (as used by unit tests)
def parse_arguments(effective_argv, wallet=None, base_iterator=None,
                    perf_iterator=None, inserted_items=None, check_only=None, **kwds):

    # effective_argv is what we are effectively given, either via the command line, via embedded
    # options in the tokenlist file, or as a result of restoring a session, before any argument
    # processing or defaulting is done (unless it's is done by argparse). Each time effective_argv
    # is changed (due to reading a tokenlist or restore file), we redo parser.parse_args() which
    # changes args, so we only do this early on before most args processing takes place.

    # If no args are present on the command line (e.g. user double-clicked the script
    # in the shell), enable --pause by default so user doesn't miss any error messages
    if not effective_argv:
        enable_pause()

    # Create a parser which can parse any supported option, and run it
    global args
    init_parser_common()
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-h", "--help",   action="store_true", help="show this help message and exit")
    parser.add_argument("--tokenlist",    metavar="FILE",      help="the list of tokens/partial passwords (required)")
    parser.add_argument("--max-tokens",   type=int, default=sys.maxint, metavar="COUNT", help="enforce a max # of tokens included per guess")
    parser.add_argument("--min-tokens",   type=int, default=1,          metavar="COUNT", help="enforce a min # of tokens included per guess")
    parser._add_container_actions(parser_common)
    parser.add_argument("--autosave",     metavar="FILE",      help="autosave (5 min) progress to or restore it from a file")
    parser.add_argument("--restore",      metavar="FILE",      help="restore progress and options from an autosave file (must be the only option on the command line)")
    parser.add_argument("--passwordlist", metavar="FILE", nargs="?", const="-", help="instead of using a tokenlist, read complete passwords (exactly one per line) from this file or from stdin")
    parser.add_argument("--has-wildcards",action="store_true", help="parse and expand wildcards inside passwordlists (default: wildcards are only parsed inside tokenlists)")
    #
    # Optional bash tab completion support
    try:
        import argcomplete
        argcomplete.autocomplete(parser)
    except ImportError:
        pass
    #
    args = parser.parse_args(effective_argv)

    # Do this as early as possible so user doesn't miss any error messages
    if args.pause: enable_pause()

    # Set the character mode early-- it's used by a large portion of the
    # rest of this module (starting with the first call to open_or_use())
    if args.utf8: mode.enable_unicode_mode()
    else:         mode.enable_ascii_mode()

    # If a simple passwordlist or base_iterator is being provided, re-parse the command line with fewer options
    # (--help is handled directly by argparse in this case)
    if args.passwordlist or base_iterator:
        parser = argparse.ArgumentParser(add_help=True)
        parser.add_argument("--passwordlist", required=not base_iterator, nargs="?", const="-", metavar="FILE", help="instead of using a tokenlist, read complete passwords (exactly one per line) from this file or from stdin")
        parser.add_argument("--has-wildcards",action="store_true", help="parse and expand wildcards inside passwordlists (default: disabled for passwordlists)")
        parser._add_container_actions(parser_common)
        # Add these in as non-options so that args gets a copy of their values
        parser.set_defaults(autosave=False, restore=False)
        args = parser.parse_args(effective_argv)

    # Manually handle the --help option, now that we know which help (tokenlist, not passwordlist) to print
    elif args.help:
        parser.print_help()
        sys.exit(0)

    # Version information is always printed by btcrecover.py, so just exit
    if args.version:
        sys.exit(0)

    if args.performance and (base_iterator or args.passwordlist or args.tokenlist):
        error_exit("--performance cannot be used with --tokenlist or --passwordlist")

    if args.list_gpus:
        devices_avail = get_opencl_devices()  # all available OpenCL device objects
        if not devices_avail:
            error_exit("no supported GPUs found")
        for i, dev in enumerate(devices_avail, 1):
            print("#"+unicode(i), dev.name.strip())
        sys.exit(0)

    # If we're not --restoring nor using a passwordlist, try to open the tokenlist_file now
    # (if we are restoring, we don't know what to open until after the restore data is loaded)
    TOKENS_AUTO_FILENAME = b"btcrecover-tokens-auto.txt"
    if not (args.restore or args.passwordlist or args.performance or base_iterator):
        tokenlist_file = open_or_use(args.tokenlist, "r", kwds.get("tokenlist"),
            default_filename=TOKENS_AUTO_FILENAME, permit_stdin=True, make_peekable=True)
        if hasattr(tokenlist_file, "name") and tokenlist_file.name.startswith(TOKENS_AUTO_FILENAME):
            enable_pause()  # enabled by default when using btcrecover-tokens-auto.txt
    else:
        tokenlist_file = None

    # If the first line of the tokenlist file starts with "#\s*--", parse it as additional arguments
    # (note that command line arguments can override arguments in this file)
    tokenlist_first_line_num = 1
    if tokenlist_file and tokenlist_file.peek() == b"#": # if it's either a comment or additional args
        first_line = tokenlist_file.readline()[1:].strip()
        tokenlist_first_line_num = 2                     # need to pass this to parse_token_list
        if first_line.startswith(b"--"):                 # if it's additional args, not just a comment
            print(b"Read additional options from tokenlist file: "+first_line, file=sys.stderr)
            tokenlist_args = first_line.split()          # TODO: support quoting / escaping?
            effective_argv = tokenlist_args + effective_argv  # prepend them so that real argv takes precedence
            args = parser.parse_args(effective_argv)     # reparse the arguments
            # Check this again as early as possible so user doesn't miss any error messages
            if args.pause: enable_pause()
            for arg in tokenlist_args:
                if arg.startswith(b"--to"):              # --tokenlist
                    error_exit("the --tokenlist option is not permitted inside a tokenlist file")
                elif arg.startswith(b"--pas"):           # --passwordlist
                    error_exit("the --passwordlist option is not permitted inside a tokenlist file")
                elif arg.startswith(b"--pe"):            # --performance
                    error_exit("the --performance option is not permitted inside a tokenlist file")
                elif arg.startswith(b"--u"):             # --utf8
                    error_exit("the --utf8 option is not permitted inside a tokenlist file")


    # There are two ways to restore from an autosave file: either specify --restore (alone)
    # on the command line in which case the saved arguments completely replace everything else,
    # or specify --autosave along with the exact same arguments as are in the autosave file.
    #
    global savestate, restored, autosave_file
    savestate = None
    restored  = False
    # If args.restore was specified, load and completely replace current arguments
    autosave_file = open_or_use(args.restore, "r+b", kwds.get("restore"))
    if autosave_file:
        if len(effective_argv) > 2 or "=" in effective_argv[0] and len(effective_argv) > 1:
            error_exit("the --restore option must be the only option when used")
        load_savestate(autosave_file)
        effective_argv = savestate[b"argv"]  # argv is effectively being replaced; it's reparsed below
        print("Restoring session:", " ".join(effective_argv))
        print("Last session ended having finished password #", savestate[b"skip"])
        restore_filename = args.restore      # save this before it's overwritten below
        args = parser.parse_args(effective_argv)
        # Check this again as early as possible so user doesn't miss any error messages
        if args.pause: enable_pause()
        # If the order of passwords generated has changed since the last version, don't permit a restore
        restored_ordering_version = savestate.get(b"ordering_version")
        if restored_ordering_version != __ordering_version__:
            if restored_ordering_version == __ordering_version__ + b"-Unicode":
                args.utf8 = True  # backwards compatibility with versions < 0.15.0
            else:
                error_exit("autosave was created with an incompatible version of "+prog)
        assert args.autosave,         "parse_arguments: autosave option enabled in restored autosave file"
        assert not args.passwordlist, "parse_arguments: passwordlist option not specified in restored autosave file"
        # If --utf8 was specified in the autosave file, it's not too late
        # to change the character mode (we haven't yet called open_or_use())
        if args.utf8: mode.enable_unicode_mode()
        #
        # We finally know the tokenlist filename; open it here
        tokenlist_file = open_or_use(args.tokenlist, "r", kwds.get("tokenlist"),
            default_filename=TOKENS_AUTO_FILENAME, permit_stdin=True, make_peekable=True)
        if hasattr(tokenlist_file, "name") and tokenlist_file.name.startswith(TOKENS_AUTO_FILENAME):
            enable_pause()  # enabled by default when using btcrecover-tokens-auto.txt
        # Display a warning if any options (all ignored) were specified in the tokenlist file
        if tokenlist_file and tokenlist_file.peek() == b"#": # if it's either a comment or additional args
            first_line = tokenlist_file.readline()
            tokenlist_first_line_num = 2                     # need to pass this to parse_token_list
            if re.match(b"#\s*--", first_line, re.UNICODE):  # if it's additional args, not just a comment
                print(prog+b": warning: all options loaded from restore file; ignoring options in tokenlist file '"+tokenlist_file.name+b"'", file=sys.stderr)
        print("Using autosave file '"+restore_filename+"'")
        args.skip = savestate[b"skip"]  # override this with the most recent value
        restored = True  # a global flag for future reference
    #
    elif args.autosave:
        # If there's anything in the specified file, assume it's autosave data and try to load it
        autosave_file = open_or_use(args.autosave, "r+b", kwds.get("autosave"), require_data=True)
        if autosave_file:
            # Load and compare to current arguments
            load_savestate(autosave_file)
            restored_argv = savestate[b"argv"]
            print("Restoring session:", " ".join(restored_argv))
            print("Last session ended having finished password #", savestate[b"skip"])
            if restored_argv != effective_argv:  # TODO: be more lenient than an exact match?
                error_exit("can't restore previous session: the command line options have changed")
            # If the order of passwords generated has changed since the last version, don't permit a restore
            if __ordering_version__ != savestate.get(b"ordering_version"):
                error_exit("autosave was created with an incompatible version of "+prog)
            print("Using autosave file '"+args.autosave+"'")
            args.skip = savestate[b"skip"]  # override this with the most recent value
            restored = True  # a global flag for future reference
        #
        # Else if the specified file is empty or doesn't exist:
        else:
            assert not (wallet or base_iterator or inserted_items), \
                        '--autosave is not supported with custom parse_arguments()'
            if args.listpass:
                print(prog+": warning: --autosave is ignored with --listpass", file=sys.stderr)
            elif args.performance:
                print(prog+": warning: --autosave is ignored with --performance", file=sys.stderr)
            else:
                # create an initial savestate that is populated throughout the rest of parse_arguments()
                savestate = dict(argv = effective_argv, ordering_version = __ordering_version__)


    # Do some basic globals initialization; the rest are all done below
    config.init_wildcards()
    init_password_generator()

    # Do a bunch of argument sanity checking

    # Either we're using a passwordlist file (though it's not yet opened),
    # or we're using a tokenlist file which should have been found and opened by now,
    # or we're running a performance test (and neither is open; already checked above).
    if not (args.passwordlist or tokenlist_file or args.performance or base_iterator or args.calc_memory):
        error_exit("argument --tokenlist or --passwordlist is required (or file "+TOKENS_AUTO_FILENAME+" must be present)")

    if tokenlist_file and args.max_tokens < args.min_tokens:
        error_exit("--max-tokens must be greater than --min-tokens")

    assert not (inserted_items and args.typos_insert), "can't specify inserted_items with --typos-insert"
    if inserted_items:
        args.typos_insert = True

    # Sanity check the --max-typos-* options
    for typo_name in itertools.chain(("swap",), config.simple_typos.keys(), ("insert",)):
        typo_max = args.__dict__["max_typos_"+typo_name]
        if typo_max < sys.maxint:
            #
            # Sanity check for when a --max-typos-* is specified, but the corresponding --typos-* is not
            if not args.__dict__["typos_"+typo_name]:
                print(prog+": warning: --max-typos-"+typo_name+" is ignored without --typos-"+typo_name, file=sys.stderr)
            #
            # Sanity check for a a --max-typos-* <= 0
            elif typo_max <= 0:
                print(prog+": warning: --max-typos-"+typo_name, typo_max, "disables --typos-"+typo_name, file=sys.stderr)
                args.__dict__["typos_"+typo_name] = None
            #
            # Sanity check --max-typos-* vs the total number of --typos
            elif args.typos and typo_max > args.typos:
                print(prog+": warning: --max-typos-"+typo_name+" ("+unicode(typo_max)+") is limited by the number of --typos ("+unicode(args.typos)+")", file=sys.stderr)

    # Sanity check --typos--closecase
    if args.typos_closecase and args.typos_case:
        print(prog+": warning: specifying --typos-case disables --typos-closecase", file=sys.stderr)
        args.typos_closecase = None

    # Build an ordered list of enabled simple typo generators. This list MUST be in the same relative
    # order as the items in config.simple_typos to prevent the breakage of --skip and --restore features
    global enabled_simple_typos
    enabled_simple_typos = tuple(
        generator for name,generator in config.simple_typos.items() if args.__dict__["typos_"+name])

    # Have _any_ (simple or otherwise) typo types been specified?
    any_typo_types_specified = enabled_simple_typos or \
        args.typos_capslock or args.typos_swap or args.typos_insert

    # Sanity check the values of --typos and --min-typos
    if not any_typo_types_specified:
        if args.min_typos > 0:
            error_exit("no passwords are produced when no type of typo is chosen, but --min-typos were required")
        if args.typos:
            print(prog+": warning: --typos has no effect because no type of typo was chosen", file=sys.stderr)
    #
    else:
        if args.typos is None:
            if args.min_typos:
                print(prog+": warning: --typos COUNT not specified; assuming same as --min_typos ("+unicode(args.min_typos)+")", file=sys.stderr)
                args.typos = args.min_typos
            else:
                print(prog+": warning: --typos COUNT not specified; assuming 1", file=sys.stderr)
                args.typos = 1
        #
        elif args.typos < args.min_typos:
            error_exit("--min_typos must be less than --typos")
        #
        elif args.typos <= 0:
            print(prog+": warning: --typos", args.typos, " disables all typos", file=sys.stderr)
            enabled_simple_typos = args.typos_capslock = args.typos_swap = args.typos_insert = inserted_items = None

    # If any simple typos have been enabled, set max_simple_typos and sum_max_simple_typos appropriately
    global max_simple_typos, sum_max_simple_typos
    if enabled_simple_typos:
        max_simple_typos = \
            [args.__dict__["max_typos_"+name] for name in config.simple_typos.keys() if args.__dict__["typos_"+name]]
        if min(max_simple_typos) == sys.maxint:    # if none were specified
            max_simple_typos     = None
            sum_max_simple_typos = sys.maxint
        elif max(max_simple_typos) == sys.maxint:  # if one, but not all were specified
            sum_max_simple_typos = sys.maxint
        else:                                      # else all were specified
            sum_max_simple_typos = sum(max_simple_typos)

    # Sanity check --max-adjacent-inserts (inserts are not a "simple" typo)
    if args.max_adjacent_inserts != 1:
        if not args.typos_insert:
            print(prog+": warning: --max-adjacent-inserts has no effect unless --typos-insert is used", file=sys.stderr)
        elif args.max_adjacent_inserts < 1:
            print(prog+": warning: --max-adjacent-inserts", args.max_adjacent_inserts, " disables --typos-insert", file=sys.stderr)
            args.typos_insert = None
        elif args.max_adjacent_inserts > min(args.typos, args.max_typos_insert):
            if args.max_typos_insert < args.typos:
                print(prog+": warning: --max-adjacent-inserts ("+unicode(args.max_adjacent_inserts)+") is limited by --max-typos-insert ("+unicode(args.max_typos_insert)+")", file=sys.stderr)
            else:
                print(prog+": warning: --max-adjacent-inserts ("+unicode(args.max_adjacent_inserts)+") is limited by the number of --typos ("+unicode(args.typos)+")", file=sys.stderr)

    # For custom inserted_items, temporarily set this to disable wildcard expansion of --insert
    if inserted_items:
        args.typos_insert = False

    # Parse the custom wildcard set option
    if args.custom_wild:
        if (args.passwordlist or base_iterator) and not \
                (args.has_wildcards or args.typos_insert or args.typos_replace):
            print(prog+": warning: ignoring unused --custom-wild", file=sys.stderr)
        else:
            args.custom_wild = mode.tstr_from_stdin(args.custom_wild)
            check_chars_range(args.custom_wild, "--custom-wild")
            custom_set_built         = build_wildcard_set(args.custom_wild)
            config.wildcard_sets[mode.tstr("c")] = custom_set_built  # (duplicates already removed by build_wildcard_set)
            config.wildcard_sets[mode.tstr("C")] = duplicates_removed(custom_set_built.upper())
            # If there are any case-sensitive letters in the set, build the case-insensitive versions
            custom_set_caseswapped = custom_set_built.swapcase()
            if custom_set_caseswapped != custom_set_built:
                config.wildcard_nocase_sets[mode.tstr("c")] = duplicates_removed(custom_set_built + custom_set_caseswapped)
                config.wildcard_nocase_sets[mode.tstr("C")] = config.wildcard_nocase_sets[mode.tstr("c")].swapcase()
            config.wildcard_keys += mode.tstr("cC")  # keep track of available wildcard types (this is used in regex's)

    # Syntax check and expand --typos-insert/--typos-replace wildcards
    # N.B. changing the iteration order below will break autosave/restore between btcr versions
    global typos_insert_expanded
    for arg_name, arg_val in ("--typos-insert", args.typos_insert), ("--typos-replace", args.typos_replace):
        if arg_val:
            arg_val = mode.tstr_from_stdin(arg_val)
            check_chars_range(arg_val, arg_name)
            count_or_error_msg = count_valid_wildcards(arg_val)
            if isinstance(count_or_error_msg, basestring):
                error_exit(arg_name, arg_val, ":", count_or_error_msg)
            if count_or_error_msg:
                load_backreference_maps_from_token(arg_val)
    if args.typos_insert:
        typos_insert_expanded  = tuple(expand_wildcards_generator(args.typos_insert))
    if args.typos_replace:
        config.typos_replace_expanded = tuple(expand_wildcards_generator(args.typos_replace))

    if inserted_items:
        args.typos_insert     = True  # undo the temporary change from above
        typos_insert_expanded = tuple(inserted_items)

    if args.delimiter:
        args.delimiter = mode.tstr_from_stdin(args.delimiter)

    # Process any --typos-map file: build a dict (typos_map) mapping replaceable characters to their replacements
    #global typos_map
    config.typos_map = None
    if args.typos_map:
        sha1 = hashlib.sha1() if savestate else None
        config.typos_map = parse_mapfile(open_or_use(args.typos_map, "r", kwds.get("typos_map")), sha1, b"--typos-map")
        #
        # If autosaving, take the hash of the typos_map and either check it
        # during a session restore to make sure we're actually restoring
        # the exact same session, or save it for future such checks
        if savestate:
            typos_map_hash = sha1.digest()
            del sha1
            if restored:
                if typos_map_hash != savestate[b"typos_map_hash"]:
                    error_exit("can't restore previous session: the typos-map file has changed")
            else:
                savestate[b"typos_map_hash"] = typos_map_hash
    #
    # Else if not args.typos_map but these were specified:
    elif (args.passwordlist or base_iterator) and args.delimiter:
        # With --passwordlist, --delimiter is only used for a --typos-map
        print(prog+": warning: ignoring unused --delimiter", file=sys.stderr)

    # Compile the regex options
    global regex_only, regex_never
    try:   regex_only  = re.compile(mode.tstr_from_stdin(args.regex_only), re.U) if args.regex_only  else None
    except re.error as e: error_exit("invalid --regex-only",  args.regex_only, ":", e)
    try:   regex_never = re.compile(mode.tstr_from_stdin(args.regex_never), re.U) if args.regex_never else None
    except re.error as e: error_exit("invalid --regex-never", args.regex_only, ":", e)

    global custom_final_checker
    custom_final_checker = check_only

    if args.skip < 0:
        print(prog+": warning: --skip must be >= 0, assuming 0", file=sys.stderr)
        args.skip = 0

    if args.threads < 1:
        print(prog+": warning: --threads must be >= 1, assuming 1", file=sys.stderr)
        args.threads = 1

    if args.worker:  # worker servers
        global worker_id, workers_total
        match = re.match(br"(\d+)/(\d+)$", args.worker)
        if not match:
            error_exit("--worker ID#/TOTAL# must be have the format uint/uint")
        worker_id     = int(match.group(1))
        workers_total = int(match.group(2))
        if workers_total < 2:
            error_exit("in --worker ID#/TOTAL#, TOTAL# must be >= 2")
        if worker_id < 1:
            error_exit("in --worker ID#/TOTAL#, ID# must be >= 1")
        if worker_id > workers_total:
            error_exit("in --worker ID#/TOTAL#, ID# must be <= TOTAL#")
        worker_id -= 1  # now it's in the range [0, workers_total)

    global have_progress, progressbar
    if args.no_progress:
        have_progress = False
    else:
        try:
            import progressbar
            have_progress = True
        except ImportError:
            have_progress = False

    # --bip39 is implied if any bip39 option is used
    for action in bip39_group._group_actions:
        if args.__dict__[action.dest]:
            args.bip39 = True
            break

    # --mkey and --privkey are deprecated synonyms of --data-extract
    if args.mkey or args.privkey:
        args.data_extract = True

    required_args = 0
    if args.wallet:       required_args += 1
    if args.data_extract: required_args += 1
    if args.bip39:        required_args += 1
    if args.listpass:     required_args += 1
    if wallet:            required_args += 1
    if required_args != 1:
        assert not wallet, 'custom wallet object not permitted with --wallet, --data-extract, --bip39, or --listpass'
        error_exit("argument --wallet (or --data-extract, --bip39, or --listpass, exactly one) is required")

    # If specificed, use a custom wallet object instead of loading a wallet file or data-extract
    if wallet:
        Wallet.set_loaded_wallet(wallet)

    # Load the wallet file (this sets the loaded_wallet global)
    if args.wallet:
        if args.android_pin:
            Wallet.set_loaded_wallet(WalletAndroidSpendingPIN.load_from_filename(args.wallet))
        elif args.blockchain_secondpass:
            Wallet.set_loaded_wallet(WalletBlockchainSecondpass.load_from_filename(args.wallet))
        elif args.wallet == "__null":
            Wallet.set_loaded_wallet(WalletNull())
        else:
            Wallet.load_global_wallet(args.wallet, settings={"options": args.msigna_keychain})
            if type(Wallet.get_loaded_wallet()) is WalletBitcoinj:
                print(prog+": notice: for MultiBit, use a .key file instead of a .wallet file if possible")
            if isinstance(Wallet.get_loaded_wallet(), WalletMultiBit) and not args.android_pin:
                print(prog+": notice: use --android-pin to recover the spending PIN of\n"
                           "    a Bitcoin Wallet for Android/BlackBerry backup (instead of the backup password)")
        if args.msigna_keychain and not isinstance(Wallet.get_loaded_wallet(), WalletMsigna):
            print(prog+": warning: ignoring --msigna-keychain (wallet file is not an mSIGNA vault)")


    # Prompt for data extracted by one of the extract-* scripts
    # instead of loading a wallet file
    if args.data_extract:
        key_crc_base64 = kwds.get("data_extract")  # for unittest
        if not key_crc_base64:
            if tokenlist_file == sys.stdin:
                print(prog+": warning: order of data on stdin is: optional extra command-line arguments, key data, rest of tokenlist", file=sys.stderr)
            elif args.passwordlist == "-" and not sys.stdin.isatty():  # if isatty, friendly prompts are provided instead
                print(prog+": warning: order of data on stdin is: key data, password list", file=sys.stderr)
            #
            key_prompt = "Please enter the data from the extract script\n> "  # the default friendly prompt
            try:
                if not sys.stdin.isatty() or sys.stdin.peeked:
                    key_prompt = "Reading extract data from stdin\n" # message to use if key data has already been entered
            except AttributeError: pass
            key_crc_base64 = raw_input(key_prompt)
        #
        # Emulates load_global_wallet(), but using the base64 key data instead of a wallet
        # file (this sets the loaded_wallet global, and returns the validated CRC)
        key_crc = Wallet.load_from_base64_key(key_crc_base64)
        #
        # Armory's extract script provides an encrypted full private key (but not the master private key nor the chaincode)
        if isinstance(Wallet.get_loaded_wallet(), WalletArmory):
            print("WARNING: an Armory private key, once decrypted, provides access to that key's Bitcoin", file=sys.stderr)
        #
        if isinstance(Wallet.get_loaded_wallet(), WalletMsigna):
            if args.msigna_keychain:
                print(prog+": warning: ignoring --msigna-keychain (the extract script has already chosen the keychain)")
        elif args.msigna_keychain:
            print(prog+": warning: ignoring --msigna-keychain (--data-extract is not from an mSIGNA vault)")
        #
        # If autosaving, either check the key_crc during a session restore to make sure we're
        # actually restoring the exact same session, or save it for future such checks
        if savestate:
            if restored:
                if key_crc != savestate[b"key_crc"]:
                    error_exit("can't restore previous session: the encrypted key entered is not the same")
            else:
                savestate[b"key_crc"] = key_crc


    # Parse --bip39 related options, and create a WalletBIP39 object
    if args.bip39:
        if args.mnemonic_prompt:
            encoding = sys.stdin.encoding or "ASCII"
            if "utf" not in encoding.lower():
                print("terminal does not support UTF; mnemonics with non-ASCII chars might not work", file=sys.stderr)
            mnemonic = raw_input("Please enter your mnemonic (seed)\n> ")
            if not mnemonic:
                sys.exit("canceled")
            if isinstance(mnemonic, str):
                mnemonic = mnemonic.decode(encoding)  # convert from terminal's encoding to unicode
        else:
            mnemonic = None

        args.wallet_type = args.wallet_type.strip().lower() if args.wallet_type else "bitcoin"
        Wallet.set_loaded_wallet(WalletBIP39(args.mpk, args.addrs, args.addr_limit, args.addressdb, mnemonic,
                                    args.language, args.bip32_path, args.wallet_type, args.performance))


    # Parse and syntax check all of the GPU related options
    if args.enable_gpu or args.calc_memory:
        if not hasattr(Wallet.get_loaded_wallet(), "init_opencl_kernel"):
            error_exit(Wallet.get_loaded_wallet().__class__.__name__ + " does not support GPU acceleration")
        if isinstance(Wallet.get_loaded_wallet(), WalletBitcoinCore) and args.calc_memory:
            error_exit("--calc-memory is not supported for Bitcoin Core wallets")
        devices_avail = get_opencl_devices()  # all available OpenCL device objects
        if not devices_avail:
            error_exit("no supported GPUs found")
        if args.int_rate <= 0:
            error_exit("--int-rate must be > 0")
        #
        # If specific devices were requested by name, build a list of devices from those available
        if args.gpu_names:
            # Create a list of names of available devices, exactly the same way as --list-gpus except all lower case
            avail_names = []  # will be the *names* of available devices
            for i, dev in enumerate(devices_avail, 1):
                avail_names.append("#"+unicode(i)+" "+dev.name.strip().lower())
            #
            devices = []  # will be the list of devices to actually use, taken from devices_avail
            for device_name in args.gpu_names:  # for each name specified at the command line
                if device_name == "":
                    error_exit("empty name in --gpus")
                device_name = device_name.lower()
                for i, avail_name in enumerate(avail_names):
                    if device_name in avail_name:  # if the name at the command line matches an available one
                        devices.append(devices_avail[i])
                        avail_names[i] = ""  # this device isn't available a second time
                        break
                else:  # if for loop exits normally, and not via the break above
                    error_exit("can't find GPU whose name contains '"+device_name+"' (use --list-gpus to display available GPUs)")
        #
        # Else if specific devices weren't requested, try to build a good default list
        else:
            best_score_sofar = -1
            for dev in devices_avail:
                cur_score = 0
                if   dev.type & pyopencl.device_type.ACCELERATOR: cur_score += 8  # always best
                elif dev.type & pyopencl.device_type.GPU:         cur_score += 4  # better than CPU
                if   "nvidia" in dev.vendor.lower():              cur_score += 2  # is never an IGP: very good
                elif "amd"    in dev.vendor.lower():              cur_score += 1  # sometimes an IGP: good
                if cur_score >= best_score_sofar:                                 # (intel is always an IGP)
                    if cur_score > best_score_sofar:
                        best_score_sofar = cur_score
                        devices = []
                    devices.append(dev)
            #
            # Multiple best devices are only permitted if they seem to be identical
            device_name = devices[0].name
            for dev in devices[1:]:
                if dev.name != device_name:
                    error_exit("can't automatically determine best GPU(s), please use the --gpu-names option")
        #
        # --global-ws and --local-ws lists must be the same length as the number of devices to use, unless
        # they are of length one in which case they are repeated until they are the correct length
        for argname, arglist in ("--global-ws", args.global_ws), ("--local-ws", args.local_ws):
            if len(arglist) == len(devices): continue
            if len(arglist) != 1:
                error_exit("number of", argname, "integers must be either one or be the number of GPUs utilized")
            arglist.extend(arglist * (len(devices) - 1))
        #
        # Check the values of --global-ws and --local-ws
        local_ws_warning = False
        if args.local_ws[0] is not None:  # if one is specified, they're all specified
            for i in xrange(len(args.local_ws)):
                if args.local_ws[i] < 1:
                    error_exit("each --local-ws must be a postive integer")
                if args.local_ws[i] > devices[i].max_work_group_size:
                    error_exit("--local-ws of", args.local_ws[i], "exceeds max of", devices[i].max_work_group_size, "for GPU '"+devices[i].name.strip()+"'")
                if args.global_ws[i] % args.local_ws[i] != 0:
                    error_exit("each --global-ws ("+unicode(args.global_ws[i])+") must be evenly divisible by its --local-ws ("+unicode(args.local_ws[i])+")")
                if args.local_ws[i] % 32 != 0 and not local_ws_warning:
                    print(prog+": warning: each --local-ws should probably be divisible by 32 for good performance", file=sys.stderr)
                    local_ws_warning = True
        for ws in args.global_ws:
            if ws < 1:
                error_exit("each --global-ws must be a postive integer")
            if isinstance(Wallet.get_loaded_wallet(), WalletArmory) and ws % 4 != 0:
                error_exit("each --global-ws must be divisible by 4 for Armory wallets")
            if ws % 32 != 0:
                print(prog+": warning: each --global-ws should probably be divisible by 32 for good performance", file=sys.stderr)
                break
        #
        extra_opencl_args = ()
        if isinstance(Wallet.get_loaded_wallet(), WalletBitcoinCore):
            if args.mem_factor != 1:
                print(prog+": warning: --mem-factor is ignored for Bitcoin Core wallets", file=sys.stderr)
        elif isinstance(Wallet.get_loaded_wallet(), WalletArmory):
            if args.mem_factor < 1:
                error_exit("--mem-factor must be >= 1")
            extra_opencl_args = args.mem_factor, args.calc_memory
        Wallet.get_loaded_wallet().init_opencl_kernel(devices, args.global_ws, args.local_ws, args.int_rate, *extra_opencl_args)
        if args.threads != parser.get_default("threads"):
            print(prog+": warning: --threads is ignored with --enable-gpu", file=sys.stderr)
        args.threads = 1
    #
    # if not --enable-gpu: sanity checks
    else:
        for argkey in "gpu_names", "global_ws", "local_ws", "int_rate", "mem_factor":
            if args.__dict__[argkey] != parser.get_default(argkey):
                print(prog+": warning: --"+argkey.replace("_", "-"), "is ignored without --enable-gpu", file=sys.stderr)


    # If specified, use a custom base password generator instead of a tokenlist or passwordlist file
    global base_password_generator, has_any_wildcards
    if base_iterator:
        assert not args.passwordlist, "can't specify --passwordlist with base_iterator"
        # (--tokenlist is already excluded by argparse when base_iterator is specified)
        base_password_generator = base_iterator
        has_any_wildcards       = args.has_wildcards  # allowed if requested

    # If specified, usa a custom password generator for performance testing
    global performance_base_password_generator
    performance_base_password_generator = perf_iterator if perf_iterator \
        else default_performance_base_password_generator

    if args.performance:
        base_password_generator = performance_base_password_generator
        has_any_wildcards       = args.has_wildcards  # allowed if requested
        if args.listpass:
            error_exit("--performance tests require a wallet or data-extract")  # or a custom checker

    # ETAs are always disabled with --listpass or --performance
    if args.listpass or args.performance:
        args.no_eta = True


    # If we're using a passwordlist file, open it here. If we're opening stdin, read in at least an
    # initial portion. If we manage to read up until EOF, then we won't need to disable ETA features.
    # TODO: support --autosave with --passwordlist files and short stdin inputs
    global passwordlist_file, initial_passwordlist, passwordlist_allcached
    passwordlist_file = open_or_use(args.passwordlist, "r", kwds.get("passwordlist"),
                                    permit_stdin=True, decoding_errors="replace")
    if passwordlist_file:
        initial_passwordlist    = []
        passwordlist_allcached  = False
        has_any_wildcards       = False
        base_password_generator = passwordlist_base_password_generator
        #
        if passwordlist_file == sys.stdin:
            passwordlist_isatty = sys.stdin.isatty()
            if passwordlist_isatty:  # be user friendly
                print("Please enter your password guesses, one per line (with no extra spaces)")
                print(exit)  # os-specific version of "Use exit() or Ctrl-D (i.e. EOF) to exit"
            else:
                print("Reading passwordlist from stdin")
            #
            for line_num in xrange(1, 1000000):
                line = passwordlist_file.readline()
                eof  = not line
                line = line.rstrip(mode.tstr("\r\n"))
                if eof or passwordlist_isatty and line == "exit()":
                    passwordlist_allcached = True
                    break
                try:
                    check_chars_range(line, "line", no_replacement_chars=True)
                except SystemExit as e:
                    passwordlist_warn(None if passwordlist_isatty else line_num, e.code)
                    line = None  # add a None to the list so we can count line numbers correctly
                if args.has_wildcards and "%" in line:
                    count_or_error_msg = count_valid_wildcards(line, permit_contracting_wildcards=True)
                    if isinstance(count_or_error_msg, basestring):
                        passwordlist_warn(None if passwordlist_isatty else line_num, count_or_error_msg)
                        line = None  # add a None to the list so we can count line numbers correctly
                    else:
                        has_any_wildcards = True
                        try:
                            load_backreference_maps_from_token(line)
                        except IOError as e:
                            passwordlist_warn(None if passwordlist_isatty else line_num, e)
                            line = None  # add a None to the list so we can count line numbers correctly
                initial_passwordlist.append(line)
            #
            if not passwordlist_allcached and not args.no_eta:
                # ETA calculations require that the passwordlist file is seekable or all in RAM
                print(prog+": warning: --no-eta has been enabled because --passwordlist is stdin and is large", file=sys.stderr)
                args.no_eta = True
        #
        if not passwordlist_allcached and args.has_wildcards:
            has_any_wildcards = True  # If not all cached, need to assume there are wildcards


    # Some final sanity checking, now that args.no_eta's value is known
    if args.no_eta:  # always true for --listpass and --performance
        if not args.no_dupchecks:
            if args.performance:
                print(prog+": warning: --performance without --no-dupchecks will eventually cause an out-of-memory error", file=sys.stderr)
            elif not args.listpass:
                print(prog+": warning: --no-eta without --no-dupchecks can cause out-of-memory failures while searching", file=sys.stderr)
        if args.max_eta != parser.get_default("max_eta"):
            print(prog+": warning: --max-eta is ignored with --no-eta, --listpass, or --performance", file=sys.stderr)


    # If we're using a tokenlist file, call parse_tokenlist() to parse it.
    if tokenlist_file:
        if tokenlist_file == sys.stdin:
            print("Reading tokenlist from stdin")
        parse_tokenlist(tokenlist_file, tokenlist_first_line_num)
        base_password_generator = tokenlist_base_password_generator


    # Open a new autosave file (if --restore was specified, the restore file
    # is still open and has already been assigned to autosave_file instead)
    if savestate and not restored:
        global autosave_nextslot
        autosave_file = open_or_use(args.autosave, "wb", kwds.get("autosave"), new_or_empty=True)
        if not autosave_file:
            error_exit("--autosave file '"+args.autosave+"' already exists, won't overwrite")
        autosave_nextslot = 0
        print("Using autosave file '"+args.autosave+"'")


    # Process any --exclude-passwordlist file: create the password_dups object earlier than normal and
    # instruct it to always consider passwords found in this file as duplicates (so they'll be skipped).
    # This is done near the end because it may take a while (all the syntax checks are done by now).
    if args.exclude_passwordlist:
        exclude_file = open_or_use(args.exclude_passwordlist, "r", kwds.get("exclude_passwordlist"), permit_stdin=True)
        if exclude_file == tokenlist_file:
            error_exit("can't use stdin for both --tokenlist and --exclude-passwordlist")
        if exclude_file == passwordlist_file:
            error_exit("can't use stdin for both --passwordlist and --exclude-passwordlist")
        #
        global password_dups
        password_dups = DuplicateChecker()
        sha1          = hashlib.sha1() if savestate else None
        try:
            for excluded_pw in exclude_file:
                excluded_pw = excluded_pw.rstrip(mode.tstr("\r\n"))
                check_chars_range(excluded_pw, "--exclude-passwordlist file")
                password_dups.exclude(excluded_pw)  # now is_duplicate(excluded_pw) will always return True
                if sha1:
                    sha1.update(excluded_pw.encode("utf_8"))
        except MemoryError:
            error_exit("not enough memory to store entire --exclude-passwordlist file")
        finally:
            if exclude_file != sys.stdin:
                exclude_file.close()
        #
        # If autosaving, take the hash of the excluded passwords and either
        # check it during a session restore to make sure we're actually
        # restoring the exact same session, or save it for future such checks
        if savestate:
            exclude_passwordlist_hash = sha1.digest()
            del sha1
            if restored:
                if exclude_passwordlist_hash != savestate[b"exclude_passwordlist_hash"]:
                    error_exit("can't restore previous session: the exclude-passwordlist file has changed")
            else:
                savestate[b"exclude_passwordlist_hash"] = exclude_passwordlist_hash
        #
        # Normally password_dups isn't even created when --no-dupchecks is specified, but it's required
        # for exclude-passwordlist; instruct the password_dups to disable future duplicate checking
        if args.no_dupchecks:
            password_dups.disable_duplicate_tracking()


    # If something has been redirected to stdin and we've been reading from it, close
    # stdin now so we don't keep the redirected files alive while running, but only
    # if we're done with it (done reading the passwordlist_file and no --pause option)
    if (    not sys.stdin.closed and not sys.stdin.isatty() and (
                args.data_extract                or
                tokenlist_file    == sys.stdin   or
                passwordlist_file == sys.stdin   or
                args.exclude_passwordlist == '-' or
                args.android_pin                 or
                args.blockchain_secondpass       or
                args.mnemonic_prompt
            ) and (
                passwordlist_file != sys.stdin   or
                passwordlist_allcached
            ) and not pause_registered ):
        sys.stdin.close()   # this doesn't really close the fd
        try:   os.close(0)  # but this should, where supported
        except StandardError: pass

    if tokenlist_file and not (pause_registered and tokenlist_file == sys.stdin):
        tokenlist_file.close()


# Builds and returns a dict (e.g. typos_map) mapping replaceable characters to their replacements.
#   map_file       -- an open file object (which this function will close)
#   running_hash   -- (opt.) adds the map's data to the hash object
#   feature_name   -- (opt.) used to generate more descriptive error messages
#   same_permitted -- (opt.) if True, the input value may be mapped to the same output value
def parse_mapfile(map_file, running_hash = None, feature_name = b"map", same_permitted = False):
    map_data = dict()
    try:
        for line_num, line in enumerate(map_file, 1):
            if line.startswith(b"#"): continue  # ignore comments
            #
            # Remove the trailing newline, then split the line exactly
            # once on the specified delimiter (default: whitespace)
            split_line = line.rstrip(mode.tstr("\r\n")).split(args.delimiter, 1)
            if split_line in ([], [mode.tstr('')]): continue  # ignore empty lines
            if len(split_line) == 1:
                error_exit(feature_name, b"file '"+map_file.name+b"' has an empty replacement list on line", line_num)
            if args.delimiter is None: split_line[1] = split_line[1].rstrip()  # ignore trailing whitespace by default

            check_chars_range(mode.tstr().join(split_line), feature_name + b" file" + (b" '" + map_file.name + b"'" if hasattr(map_file, "name") else b""))
            for c in split_line[0]:  # (c is the character to be replaced)
                replacements = duplicates_removed(map_data.get(c, mode.tstr()) + split_line[1])
                if not same_permitted and c in replacements:
                    map_data[c] = filter(lambda r: r != c, replacements)
                else:
                    map_data[c] = replacements
    finally:
        map_file.close()

    # If autosaving, take a hash of the map_data so it can either be checked (later)
    # during a session restore to make sure we're actually restoring the exact same
    # session, or can be saved for future such checks
    if running_hash:
        for k in sorted(map_data.keys()):  # must take the hash in a deterministic order (not in map_data order)
            v = map_data[k]
            running_hash.update(k.encode("utf_8") + v.encode("utf_8"))

    return map_data


################################### Tokenfile Parsing ###################################


# Build up the token_lists structure, a list of lists, reflecting the tokenlist file.
# Each list in the token_lists list is preceded with a None element unless the
# corresponding line in the tokenlist file begins with a "+" (see example below).
# Each token is represented by a string if that token is not anchored, or by an
# AnchoredToken object used to store the begin and end fields
#
# EXAMPLE FILE:
#     #   Lines that begin with # are ignored comments
#     #
#     an_optional_token_exactly_one_per_line...
#     ...may_or_may_not_be_tried_per_guess
#     #
#     mutually_exclusive  token_list  on_one_line  at_most_one_is_tried
#     #
#     +  this_required_token_was_preceded_by_a_plus_in_the_file
#     +  exactly_one_of_these  tokens_are_required  and_were_preceded_by_a_plus
#     #
#     ^if_present_this_is_at_the_beginning  if_present_this_is_at_the_end$
#     #
#     ^2$if_present_this_is_second ^5$if_present_this_is_fifth
#     #
#     ^2,4$if_present_its_second_third_or_fourth_(but_never_last)
#     ^2,$if_present_this_is_second_or_greater_(but_never_last)
#     ^,$exactly_the_same_as_above
#     ^,3$if_present_this_is_third_or_less_(but_never_first_or_last)
#
# RESULTANT token_lists ==
# [
#     [ None,  'an_optional_token_exactly_one_per_line...' ],
#     [ None,  '...may_or_may_not_be_tried_per_guess' ],
#
#     [ None,  'mutually_exclusive',  'token_list',  'on_one_line',  'at_most_one_is_tried' ],
#
#     [ 'this_required_token_was_preceded_by_a_plus_in_the_file' ],
#     [ 'exactly_one_of_these',  'tokens_are_required',  'and_were_preceded_by_a_plus' ],
#
#     [ AnchoredToken(begin=0), AnchoredToken(begin="$") ],
#
#     [ AnchoredToken(begin=1), AnchoredToken(begin=4) ],
#
#     [ AnchoredToken(begin=1, end=3) ],
#     [ AnchoredToken(begin=1, end=sys.maxint) ],
#     [ AnchoredToken(begin=1, end=sys.maxint) ],
#     [ AnchoredToken(begin=1, end=2) ]
# ]

# After creation, AnchoredToken must not be changed: it creates and caches the return
# values for __str__ and __hash__ for speed on the assumption they don't change
class AnchoredToken(object):
    # The possible values for the .type attribute:
    POSITIONAL = 1  # has a .pos attribute
    RELATIVE   = 2  # same as ^
    MIDDLE     = 3  # has .begin and .end attributes

    def __init__(self, token, line_num = "?"):
        if token.startswith(b"^"):
            # If it is a syntactically correct positional, relative, or middle anchor
            match = re.match(br"\^(?:(?P<begin>\d+)?(?P<middle>,)(?P<end>\d+)?|(?P<rel>[rR])?(?P<pos>\d+))[\^$]", token)
            if match:
                # If it's a middle (ranged) anchor
                if match.group(b"middle"):
                    begin = match.group(b"begin")
                    end   = match.group(b"end")
                    cached_str = mode.tstr("^")  # begin building the cached __str__
                    if begin is None:
                        begin = 2
                    else:
                        begin = int(begin)
                        if begin > 2:
                            cached_str += mode.tstr(begin)
                    cached_str += mode.tstr(",")
                    if end is None:
                        end = sys.maxint
                    else:
                        end = int(end)
                        cached_str += mode.tstr(end)
                    cached_str += mode.tstr("^")
                    if begin > end:
                        error_exit("anchor range of token on line", line_num, "is invalid (begin > end)")
                    if begin < 2:
                        error_exit("anchor range of token on line", line_num, "must begin with 2 or greater")
                    self.type  = AnchoredToken.MIDDLE
                    self.begin = begin - 1
                    self.end   = end   - 1 if end != sys.maxint else end
                #
                # If it's a positional or relative anchor
                elif match.group(b"pos"):
                    pos = int(match.group(b"pos"))
                    cached_str = mode.tstr("^")  # begin building the cached __str__
                    if match.group(b"rel"):
                        cached_str += mode.tstr("r") + mode.tstr(pos) + mode.tstr("^")
                        self.type = AnchoredToken.RELATIVE
                        self.pos  = pos
                    else:
                        if pos < 1:
                            error_exit("anchor position of token on line", line_num, "must be 1 or greater")
                        if pos > 1:
                            cached_str += mode.tstr(pos) + mode.tstr("^")
                        self.type = AnchoredToken.POSITIONAL
                        self.pos  = pos - 1
                #
                else:
                    assert False, "AnchoredToken.__init__: determined anchor type"

                self.text = token[match.end():]  # same for positional, relative, and middle anchors
            #
            # Else it's a begin anchor
            else:
                if len(token) > 1 and token[1] in b"0123456789,":
                    print(prog+": warning: token on line", line_num, "looks like it might be a positional or middle anchor, " +
                          "but it can't be parsed correctly, so it's assumed to be a simple beginning anchor instead", file=sys.stderr)
                if len(token) > 2 and token[1].lower() == b"r" and token[2] in b"0123456789":
                    print(prog+": warning: token on line", line_num, "looks like it might be a relative anchor, " +
                          "but it can't be parsed correctly, so it's assumed to be a simple beginning anchor instead", file=sys.stderr)
                cached_str = mode.tstr("^")  # begin building the cached __str__
                self.type  = AnchoredToken.POSITIONAL
                self.pos   = 0
                self.text  = token[1:]
            #
            if self.text.endswith(b"$"):
                error_exit("token on line", line_num, "is anchored with both ^ at the beginning and $ at the end")
            #
            cached_str += self.text  # finish building the cached __str__
        #
        # Parse end anchor if present
        elif token.endswith(b"$"):
            cached_str = token
            self.type  = AnchoredToken.POSITIONAL
            self.pos   = b"$"
            self.text  = token[:-1]
        #
        else: raise ValueError("token passed to AnchoredToken constructor is not an anchored token")
        #
        self.cached_str  = intern(cached_str) if type(cached_str) is str else cached_str
        self.cached_hash = hash(self.cached_str)
        if self.text == "":
            print(prog+": warning: token on line", line_num, "contains only an anchor (and zero password characters)", file=sys.stderr)

    # For sets
    def __hash__(self):      return self.cached_hash
    def __eq__(self, other): return     isinstance(other, AnchoredToken) and self.cached_str == other.cached_str
    def __ne__(self, other): return not isinstance(other, AnchoredToken) or  self.cached_str != other.cached_str
    # For sort (so that mode.tstr() can be used as the key function)
    def __str__(self):       return     str(self.cached_str)
    def __unicode__(self):   return unicode(self.cached_str)
    # For hashlib
    def __repr__(self):      return self.__class__.__name__ + b"(" + repr(self.cached_str) + b")"

def parse_tokenlist(tokenlist_file, first_line_num = 1):
    global token_lists
    global has_any_duplicate_tokens, has_any_wildcards, has_any_anchors

    if args.no_dupchecks < 3:
        has_any_duplicate_tokens = False
        token_set_for_dupchecks  = set()
    has_any_wildcards   = False
    has_any_anchors     = False
    token_lists         = []

    for line_num, line in enumerate(tokenlist_file, first_line_num):

        # Ignore comments
        if line.startswith(b"#"):
            if re.match(b"#\s*--", line, re.UNICODE):
                print(prog+": warning: all options must be on the first line, ignoring options on line", unicode(line_num), file=sys.stderr)
            continue

        # Start off assuming these tokens are optional (no preceding "+");
        # if it turns out there is a "+", we'll remove this None later
        new_list = [None]

        # Remove the trailing newline, then split the line on the
        # specified delimiter (default: whitespace) to get a list of tokens
        new_list.extend(line.rstrip(mode.tstr("\r\n")).split(args.delimiter))

        # Ignore empty lines
        if new_list in ([None], [None, mode.tstr('')]): continue

        # If a "+" is present at the beginning followed by at least one token,
        # then exactly one of the token(s) is required. This is noted in the structure
        # by removing the preceding None we added above (and also delete the "+")
        if new_list[1] == b"+" and len(new_list) > 2:
            del new_list[0:2]

        # Check token syntax and convert any anchored tokens to an AnchoredToken object
        for i, token in enumerate(new_list):
            if token is None: continue

            check_chars_range(token, "token on line " + unicode(line_num))

            # Syntax check any wildcards, and load any wildcard backreference maps
            count_or_error_msg = count_valid_wildcards(token, permit_contracting_wildcards=True)
            if isinstance(count_or_error_msg, basestring):
                error_exit("on line", unicode(line_num)+":", count_or_error_msg)
            elif count_or_error_msg:
                has_any_wildcards = True  # (a global)
                load_backreference_maps_from_token(token)

            # Check for tokens which look suspiciously like command line options
            # (using a private ArgumentParser member func is asking for trouble...)
            if token.startswith(b"--") and parser_common._get_option_tuples(token):
                if line_num == 1:
                    print(prog+": warning: token on line 1 looks like an option, "
                               "but line 1 did not start like this: #--option1 ...", file=sys.stderr)
                else:
                    print(prog+": warning: token on line", unicode(line_num), "looks like an option, "
                               " but all options must be on the first line", file=sys.stderr)

            # Parse anchor if present and convert to an AnchoredToken object
            if token.startswith(b"^") or token.endswith(b"$"):
                token = AnchoredToken(token, line_num)  # (the line_num is just for error messages)
                new_list[i] = token
                has_any_anchors = True

            # Keep track of the existence of any duplicate tokens for future optimization
            if args.no_dupchecks < 3 and not has_any_duplicate_tokens:
                if token in token_set_for_dupchecks:
                    has_any_duplicate_tokens = True
                    del token_set_for_dupchecks
                else:
                    token_set_for_dupchecks.add(token)

        # Add the completed list for this one line to the token_lists list of lists
        token_lists.append(new_list)

    # Tokens at the end of the outer token_lists get tried first below;
    # reverse the list here so that tokens at the beginning of the file
    # appear at the end of the list and consequently get tried first
    token_lists.reverse()

    # If autosaving, take a hash of the token_lists and backreference maps, and
    # either check them during a session restore to make sure we're actually
    # restoring the exact same session, or save them for future such checks
    if savestate:
        token_lists_hash        = hashlib.sha1(repr(token_lists)).digest()
        backreference_maps_hash = config.backreference_maps_sha1.digest() if config.backreference_maps_sha1 else None
        if restored:
            if token_lists_hash != savestate[b"token_lists_hash"]:
                error_exit("can't restore previous session: the tokenlist file has changed")
            if backreference_maps_hash != savestate.get(b"backreference_maps_hash"):
                error_exit("can't restore previous session: one or more backreference maps have changed")
        else:
            savestate[b"token_lists_hash"] = token_lists_hash
            if backreference_maps_hash:
                savestate[b"backreference_maps_hash"] = backreference_maps_hash


# Load any map files referenced in wildcard backreferences in the passed token
def load_backreference_maps_from_token(token):
    #global config.backreference_maps       # initialized to dict() in config.init_wildcards()
    #global config.backreference_maps_sha1  # initialized to  None  in config.init_wildcards()
    # We know all wildcards present have valid syntax, so we don't need to use the full regex, but
    # we do need to capture %% to avoid parsing this as a backreference (it isn't one): %%;file;b
    for map_filename in re.findall(br"%[\d,]*;(.+?);\d*b|%%", token):
        if map_filename and map_filename not in config.backreference_maps:
            if savestate and not config.backreference_maps_sha1:
                config.backreference_maps_sha1 = hashlib.sha1()
            config.backreference_maps[map_filename] = \
                parse_mapfile(open(map_filename, "r"), config.backreference_maps_sha1, b"backreference map", same_permitted=True)


################################### Password Generation ###################################


# Checks for duplicate hashable items in multiple identical runs
# (builds a cache in the first run to be memory efficient in future runs)
class DuplicateChecker(object):

    EXCLUDE = sys.maxint

    def __init__(self):
        self._seen_once  = dict()  # tracks potential duplicates in run 0 only
        self._duplicates = dict()  # tracks having seen known duplicates in runs 1+
        self._run_number = 0       # incremented at the end of each run
        self._tracking   = True    # is duplicate tracking enabled?
                                   # (even if False, excluded items are still checked)

    # Returns True if x has already been seen in this run. If x has been
    # excluded, always returns True (even if it hasn't been seen yet).
    def is_duplicate(self, x):

        # The duplicates cache is built during the first run
        if self._run_number == 0:
            if x in self._duplicates:  # If it's the third+ time we've seen it (or 2nd+ & excluded):
                return True
            if x in self._seen_once:   # If it's the second time we've seen it, or it's excluded:
                self._duplicates[x] = self._seen_once.pop(x)  # move it to list of known duplicates
                return True
            # Otherwise it's the first time we've seen it
            if self._tracking:
                self._seen_once[x] = 1
            return False

        # The duplicates cache is available for lookup on second+ runs
        duplicate = self._duplicates.get(x)            # ==sys.maxint if it's excluded
        if duplicate:
            if duplicate <= self._run_number:          # First time we've seen it this run:
                self._duplicates[x] = self._run_number + 1  # mark it as having been seen this run
                return False
            else:                                     # Second+ time we've seen it this run, or it's excluded:
                return True
        return False                                  # Else it isn't a recorded duplicate

    # Adds x to the already-seen dict such that is_duplicate(x) will always return True
    def exclude(self, x):
        self._seen_once[x] = self.EXCLUDE

    # Future duplicates will be ignored (and will not consume additional memory), however
    # is_duplicate() will still return True for duplicates and exclusions seen/added so far
    def disable_duplicate_tracking(self):
        self._tracking = False

    # Must be called before the same list of items is revisited
    def run_finished(self):
        if self._run_number == 0:
            del self._seen_once  # No longer need this for second+ runs
        self._run_number += 1


# The main generator function produces all possible requested password permutations with no
# duplicates from the token_lists global as constructed above plus wildcard expansion or from
# the passwordlist file, plus up to a certain number of requested typos. Results are produced
# in lists of length chunksize, which can be changed by calling iterator.send((new_chunksize,
# only_yield_count)) (which does not itself return any passwords). If only_yield_count, then
# instead of producing lists, for each iteration single integers <= chunksize are produced
# (only the last integer might be < than chunksize), useful for counting or skipping passwords.
def init_password_generator():
    global password_dups, token_combination_dups, passwordlist_warnings
    password_dups = token_combination_dups = None
    passwordlist_warnings = 0
    # (re)set the min_typos argument default values to 0
    capslock_typos_generator.func_defaults = (0,)
    swap_typos_generator    .func_defaults = (0,)
    simple_typos_generator  .func_defaults = (0,)
    insert_typos_generator  .func_defaults = (0,)


#def shouldPrintProgress()


def password_generator(chunksize = 1, only_yield_count = False):
    assert chunksize > 0, "password_generator: chunksize > 0"
    # Used to communicate between typo generators the number of typos that have been
    # created so far during each password generated so that later generators know how
    # many additional typos, at most, they are permitted to add, and also if it is
    # the last typo generator that will run, how many, at least, it *must* add
    global typos_sofar
    typos_sofar = 0

    passwords_gathered = []
    passwords_count = 0  # == len(passwords_gathered)
    worker_count = 0  # Only used if --worker is specified
    new_args = None

    # Initialize this global if not already initialized but only
    # if they should be used; see its usage below for more details
    global password_dups
    if password_dups is None and args.no_dupchecks < 1:
        password_dups = DuplicateChecker()

    # Copy a few globals into local for a small speed boost
    l_generator_product = generator_product
    l_regex_only        = regex_only
    l_regex_never       = regex_never
    l_password_dups     = password_dups
    l_args_worker       = args.worker
    if l_args_worker:
        l_workers_total = workers_total
        l_worker_id     = worker_id

    # Build up the modification_generators list; see the inner loop below for more details
    modification_generators = []
    if has_any_wildcards:    modification_generators.append(expand_wildcards_generator )
    if args.typos_capslock:  modification_generators.append(capslock_typos_generator   )
    if args.typos_swap:      modification_generators.append(swap_typos_generator       )
    if enabled_simple_typos: modification_generators.append(simple_typos_generator     )
    if args.typos_insert:    modification_generators.append(insert_typos_generator     )
    modification_generators_len = len(modification_generators)

    # Only the last typo generator needs to enforce a min-typos requirement
    if args.min_typos:
        assert modification_generators[-1] != expand_wildcards_generator
        # set the min_typos argument default value
        modification_generators[-1].func_defaults = (args.min_typos,)

    total_counted_passwords = 0
    num_batches_between_updates = 10
    current_batch_mod = 0

    # The base password generator is set in parse_arguments(); it's either an iterable
    # or a generator function (which returns an iterator) that produces base passwords
    # usually based on either a tokenlist file (as parsed above) or a passwordlist file.
    for password_base in base_password_generator() if callable(base_password_generator) else base_password_generator:

        # The for loop below takes the password_base and applies zero or more modifications
        # to it to produce a number of different possible variations of password_base (e.g.
        # different wildcard expansions, typos, etc.)

        # modification_generators is a list of function generators each of which takes a
        # string and produces one or more password variations based on that string. It is
        # built just above, and is built differently depending on the token_lists (are any
        # wildcards present?) and the program options (were any typos requested?).
        #
        # If any modifications have been requested, create an iterator that will
        # loop through all combinations of the requested modifications
        if modification_generators_len:
            if modification_generators_len == 1:
                modification_iterator = modification_generators[0](password_base)
            else:
                modification_iterator = l_generator_product(password_base, *modification_generators)
        #
        # Otherwise just produce the unmodified password itself
        else:
            modification_iterator = (password_base,)

        for password in modification_iterator:

            # Check the password against the --regex-only and --regex-never options
            if l_regex_only and not l_regex_only .search(password):
                continue
            if l_regex_never and l_regex_never.search(password):
                continue

            # This is the check_only argument optionally passed
            # by external libraries to parse_arguments()
            if custom_final_checker and not custom_final_checker(password):
                continue

            # This duplicate check can be disabled via --no-dupchecks
            # because it can take up a lot of memory, sometimes needlessly
            if l_password_dups and l_password_dups.is_duplicate(password):
                continue

            # Workers in a server pool ignore passwords not assigned to them
            if l_args_worker:
                if worker_count % l_workers_total != l_worker_id:
                    worker_count += 1
                    continue
                worker_count += 1

            # Produce the password(s) or the count once enough of them have been accumulated
            passwords_count += 1
            if only_yield_count:
                if passwords_count >= chunksize:
                    new_args = yield passwords_count
                    passwords_count = 0
            else:
                passwords_gathered.append(password)
                if passwords_count >= chunksize:
                    total_counted_passwords += passwords_count
                    current_batch_mod += 1
                    if current_batch_mod == num_batches_between_updates:
                        print(str(total_counted_passwords) + "; {:.6f}%"
                              .format((total_counted_passwords / args.est_passwords) * 100))

                        current_batch_mod %= num_batches_between_updates

                    new_args = yield passwords_gathered
                    passwords_gathered = []
                    passwords_count = 0

            # Process new arguments received from .send(), yielding nothing back to send()
            if new_args:
                chunksize, only_yield_count = new_args
                assert chunksize > 0, "password_generator.send: chunksize > 0"
                new_args = None
                yield

        assert typos_sofar == 0, "password_generator: typos_sofar == 0 after all typo generators have finished"

    if l_password_dups: l_password_dups.run_finished()

    # Produce the remaining passwords that have been accumulated
    if passwords_count > 0:
        yield passwords_count if only_yield_count else passwords_gathered


# This generator utility is a bit like itertools.product. It takes a list of iterators
# and invokes them in (the equivalent of) a nested for loop, except instead of a list
# of simple iterators it takes a list of generators each of which expects to be called
# with a single argument. generator_product calls the first generator with the passed
# initial_value, and then takes each value it produces and calls the second generator
# with each, and then takes each value the second generator produces and calls the
# third generator with each, etc., until there are no generators left, at which point
# it produces all the values generated by the last generator.
#
# This can be useful in the case you have a list of generators, each of which is
# designed to produce a number of variations of an initial value, and you'd like to
# string them together to get all possible (product-wise) variations.
#
# TODO: implement without recursion?
def generator_product(initial_value, generator, *other_generators):
    if other_generators == ():
        for final_value in generator(initial_value):
            yield final_value
    else:
        for intermediate_value in generator(initial_value):
            for final_value in generator_product(intermediate_value, *other_generators):
                yield final_value


# The tokenlist generator function produces all possible password permutations from the
# token_lists global as constructed by parse_tokenlist(). These passwords are then used
# by password_generator() as base passwords that can undergo further modifications.
def tokenlist_base_password_generator():
    # Initialize this global if not already initialized but only
    # if they should be used; see its usage below for more details
    global token_combination_dups
    if token_combination_dups is None and args.no_dupchecks < 2 and has_any_duplicate_tokens:
        token_combination_dups = DuplicateChecker()

    # Copy a few globals into local for a small speed boost
    l_len                    = len
    l_args_min_tokens        = args.min_tokens
    l_args_max_tokens        = args.max_tokens
    l_has_any_anchors        = has_any_anchors
    l_type                   = type
    l_token_combination_dups = token_combination_dups
    l_tuple                  = tuple
    l_sorted                 = sorted
    l_list                   = list
    l_tstr                   = mode.tstr

    # Choose between the custom duplicate-checking and the standard itertools permutation
    # functions for the outer loop unless the custom one has been specifically disabled
    # with three (or more) --no-dupcheck options.
    if args.no_dupchecks < 3 and has_any_duplicate_tokens:
        permutations_function = permutations_nodups
    else:
        permutations_function = itertools.permutations

    # The outer loop iterates through all possible (unordered) combinations of tokens
    # taking into account the at-most-one-token-per-line rule. Note that lines which
    # were not required (no "+") have a None in their corresponding list; if this
    # None item is chosen for a tokens_combination, then this tokens_combination
    # corresponds to one without any token from that line, and we we simply remove
    # the None from this tokens_combination (product_limitedlen does this on its own,
    # itertools.product does not so it's done below).
    #
    # First choose which product generator to use: the custom product_limitedlen
    # might be faster (possibly a lot) if a large --min-tokens or any --max-tokens
    # is specified at the command line, otherwise use the standard itertools version.
    using_product_limitedlen = l_args_min_tokens > 5 or l_args_max_tokens < sys.maxint
    if using_product_limitedlen:
        product_generator = product_limitedlen(*token_lists, minlen=l_args_min_tokens, maxlen=l_args_max_tokens)
    else:
        product_generator = itertools.product(*token_lists)
    for tokens_combination in product_generator:

        # Remove any None's, then check against token length constraints:
        # (product_limitedlen, if used, has already done all this)
        if not using_product_limitedlen:
            tokens_combination = filter(lambda t: t is not None, tokens_combination)
            if not l_args_min_tokens <= l_len(tokens_combination) <= l_args_max_tokens: continue

        # There are three types of anchors: positional, middle/range, & relative. Positionals
        # only have a single possible position; middle anchors have a range, but are never
        # tried at the beginning or end; relative anchors appear in a certain order with
        # respect to each other. Below, build a tokens_combination_nopos list from
        # tokens_combination with all positional anchors removed. They will be inserted
        # back into the correct position later. Also search for invalid anchors of any
        # type\: a positional anchor placed past the end of the current combination (based
        # on its length) or a middle anchor whose begin position is past *or at* the end.
        positional_anchors  = None  # (will contain strings, not AnchoredToken's)
        has_any_mid_anchors = False
        rel_anchors_count   = 0
        if l_has_any_anchors:
            tokens_combination_len   = l_len(tokens_combination)
            tokens_combination_nopos = []  # all tokens except positional ones
            invalid_anchors          = False
            for token in tokens_combination:
                if l_type(token) == AnchoredToken:
                    if token.type == AnchoredToken.POSITIONAL:  # a single-position anchor
                        pos = token.pos
                        if pos == b"$":
                            pos = tokens_combination_len - 1
                        elif pos >= tokens_combination_len:
                            invalid_anchors = True  # anchored past the end
                            break
                        if not positional_anchors:  # initialize it to a list of None's
                            positional_anchors = [None for i in xrange(tokens_combination_len)]
                        elif positional_anchors[pos] is not None:
                            invalid_anchors = True  # two tokens anchored to the same place
                            break
                        positional_anchors[pos] = token.text    # save valid single-position anchor
                    elif token.type == AnchoredToken.MIDDLE:    # a middle/range anchor
                        if token.begin+1 >= tokens_combination_len:
                            invalid_anchors = True  # anchored past *or at* the end
                            break
                        tokens_combination_nopos.append(token)  # add this token (a middle anchor)
                        has_any_mid_anchors = True
                    else:                                       # else it must be a relative anchor,
                        tokens_combination_nopos.append(token)  # add it
                        rel_anchors_count += 1
                else:                                           # else it's not an anchored token,
                    tokens_combination_nopos.append(token)      # add this token (just a string)
            if invalid_anchors: continue
            #
            if tokens_combination_nopos == []:              # if all tokens have positional anchors,
                tokens_combination_nopos = ( l_tstr(""), )  # make this non-empty so a password can be created
        else:
            tokens_combination_nopos = tokens_combination

        # Do some duplicate checking early on to avoid running through potentially a
        # lot of passwords all of which end up being duplicates. We check the current
        # combination (of all tokens), sorted because different orderings of token
        # combinations are equivalent at this point. This check can be disabled with two
        # (or more) --no-dupcheck options (one disables only the full duplicate check).
        # TODO:
        #   Be smarter in deciding when to enable this? (currently on if has_any_duplicate_tokens)
        #   Instead of dup checking, write a smarter product (seems hard)?
        if l_token_combination_dups and \
           l_token_combination_dups.is_duplicate(l_tuple(l_sorted(tokens_combination, key=l_tstr))): continue

        # The inner loop iterates through all valid permutations (orderings) of one
        # combination of tokens and combines the tokens to create a password string.
        # Because positionally anchored tokens can only appear in one position, they
        # are not passed to the permutations_function.
        for ordered_token_guess in permutations_function(tokens_combination_nopos):

            # If multiple relative anchors are in a guess, they must appear in the correct
            # relative order. If any are out of place, we continue on to the next guess.
            # Otherwise, we remove the anchor information leaving only the string behind.
            if rel_anchors_count:
                invalid_anchors   = False
                last_relative_pos = 0
                for i, token in enumerate(ordered_token_guess):
                    if l_type(token) == AnchoredToken and token.type == AnchoredToken.RELATIVE:
                        if token.pos < last_relative_pos:
                            invalid_anchors = True
                            break
                        if l_type(ordered_token_guess) != l_list:
                            ordered_token_guess = l_list(ordered_token_guess)
                        ordered_token_guess[i] = token.text  # now it's just a string
                        if rel_anchors_count == 1:  # with only one, it's always valid
                            break
                        last_relative_pos = token.pos
                if invalid_anchors: continue

            # Insert the positional anchors we removed above back into the guess
            if positional_anchors:
                ordered_token_guess = l_list(ordered_token_guess)
                for i, token in enumerate(positional_anchors):
                    if token is not None:
                        ordered_token_guess.insert(i, token)  # (token here is just a string)

            # The last type of anchor has a range of possible positions for the anchored
            # token. If any anchored token is outside of its permissible range, we continue
            # on to the next guess. Otherwise, we remove the anchor information leaving
            # only the string behind.
            if has_any_mid_anchors:
                if l_type(ordered_token_guess[0])  == AnchoredToken or \
                   l_type(ordered_token_guess[-1]) == AnchoredToken:
                    continue  # middle anchors are never permitted at the beginning or end
                invalid_anchors = False
                for i, token in enumerate(ordered_token_guess[1:-1], 1):
                    if l_type(token) == AnchoredToken:
                        assert token.type == AnchoredToken.MIDDLE, "only middle/range anchors left"
                        if token.begin <= i <= token.end:
                            if l_type(ordered_token_guess) != l_list:
                                ordered_token_guess = l_list(ordered_token_guess)
                            ordered_token_guess[i] = token.text  # now it's just a string
                        else:
                            invalid_anchors = True
                            break
                if invalid_anchors: continue

            yield l_tstr().join(ordered_token_guess)

    if l_token_combination_dups: l_token_combination_dups.run_finished()


# Like itertools.product, but only produces output tuples whose length is between
# minlen and maxlen. Normally, product always produces output of length len(sequences),
# but this version removes elements from each produced product which are == None
# (making their length variable) and only then applies the requested length constraint.
# (Does not accept the itertools "repeat" argument.)
# TODO: implement without recursion?
#
# Check for edge cases that would violate do_product_limitedlen()'s invariants,
# and then call do_product_limitedlen() to do the real work
def product_limitedlen(*sequences, **kwds):
    minlen = max(kwds.get("minlen", 0), 0)  # no less than 0
    maxlen = kwds.get("maxlen", sys.maxint)

    if minlen > maxlen:  # minlen is already >= 0
        return xrange(0).__iter__()         # yields nothing at all

    if maxlen == 0:      # implies minlen == 0 because of the check above
        # Produce a length 0 tuple unless there's a seq which doesn't have a None
        # (and therefore would produce output of length >= 1, but maxlen == 0)
        for seq in sequences:
            if None not in seq: break
        else:  # if it didn't break, there was a None in every seq
            return itertools.repeat((), 1)  # a single empty tuple
        # if it did break, there was a seq without a None
        return xrange(0).__iter__()         # yields nothing at all

    sequences_len = len(sequences)
    if sequences_len == 0:
        if minlen == 0:  # already true: minlen >= 0 and maxlen >= minlen
            return itertools.repeat((), 1)  # a single empty tuple
        else:            # else minlen > 0
            return xrange(0).__iter__()     # yields nothing at all

    # If there aren't enough sequences to satisfy minlen
    if minlen > sequences_len:
        return xrange(0).__iter__()         # yields nothing at all

    # Unfortunately, do_product_limitedlen is recursive; the recursion limit
    # must be at least as high as sequences_len plus a small buffer
    if sequences_len + 20 > sys.getrecursionlimit():
        sys.setrecursionlimit(sequences_len + 20)

    # Build a lookup table for do_product_limitedlen() (see below for details)
    requireds_left_sofar = 0
    requireds_left = [None]  # requireds_left[0] is never used
    for seq in reversed(sequences[1:]):
        if None not in seq: requireds_left_sofar += 1
        requireds_left.append(requireds_left_sofar)

    return do_product_limitedlen(minlen, maxlen, requireds_left, sequences_len - 1, *sequences)
#
# assumes: maxlen >= minlen, maxlen >= 1, others_len == len(other_sequences), others_len + 1 >= minlen
def do_product_limitedlen(minlen, maxlen, requireds_left, others_len, sequence, *other_sequences):
    # When there's only one sequence
    if others_len == 0:
        # If minlen == 1, produce everything but empty tuples
        # (since others_len + 1 >= minlen, minlen is 1 or less)
        if minlen == 1:
            for choice in sequence:
                if choice is not None: yield (choice,)
        # Else everything is produced
        else:
            for choice in sequence:
                yield () if choice is None else (choice,)
        return

    # Iterate through elements in the first sequence
    for choice in sequence:

        # Adjust minlen and maxlen if this element affects the length (isn't None)
        # and check that the invariants aren't violated
        if choice is None:
            # If all possible results will end up being shorter than the specified minlen:
            if others_len < minlen:
                continue
            new_minlen = minlen
            new_maxlen = maxlen

            # Expand the other_sequences (the current choice doesn't contribute because it's None)
            for rest in do_product_limitedlen(new_minlen, new_maxlen, requireds_left, others_len - 1, *other_sequences):
                yield rest

        else:
            new_minlen = minlen - 1
            new_maxlen = maxlen - 1
            # requireds_left[others_len] is a count of remaining sequences which do not
            # contain a None: they are "required" and will definitely add to the length
            # of the final result. If all possible results will end up being longer than
            # the specified maxlen:
            if requireds_left[others_len] > new_maxlen:
                continue
            # If new_maxlen == 0, then the only valid result is the one where all of the
            # other_sequences produce a None for their choice. Produce that single result:
            if new_maxlen == 0:
                yield (choice,)
                continue

            # Prepend the choice to the result of expanding the other_sequences
            for rest in do_product_limitedlen(new_minlen, new_maxlen, requireds_left, others_len - 1, *other_sequences):
                yield (choice,) + rest


# Like itertools.permutations, but avoids duplicates even if input contains some.
# Input must be a sequence of hashable elements. (Does not accept the itertools "r" argument.)
# TODO: implement without recursion?
def permutations_nodups(sequence):
    # Copy a global into local for a small speed boost
    l_len = len

    sequence_len = l_len(sequence)

    # Special case for speed
    if sequence_len == 2:
        # Only two permutations to try:
        yield sequence if type(sequence) == tuple else tuple(sequence)
        if sequence[0] != sequence[1]:
            yield (sequence[1], sequence[0])
        return

    # If they're all the same, there's only one permutation:
    seen = set(sequence)
    if l_len(seen) == 1:
        yield sequence if type(sequence) == tuple else tuple(sequence)
        return

    # If the sequence contains no duplicates, use the faster itertools version
    if l_len(seen) == sequence_len:
        for permutation in itertools.permutations(sequence):
            yield permutation
        return

    # Else there's at least one duplicate and two+ permutations; use our version
    seen = set()
    for i, choice in enumerate(sequence):
        if i > 0 and choice in seen: continue          # don't need to check the first one
        if i+1 < sequence_len:       seen.add(choice)  # don't need to add the last one
        for rest in permutations_nodups(sequence[:i] + sequence[i+1:]):
            yield (choice,) + rest


MAX_PASSWORDLIST_WARNINGS = 100
def passwordlist_warn(line_num, *args):
    global passwordlist_warnings  # initialized to 0 in init_password_generator()
    if passwordlist_warnings is not None:
        passwordlist_warnings += 1
        if passwordlist_warnings <= MAX_PASSWORDLIST_WARNINGS:
            print(prog+": warning: ignoring",
                  "line "+unicode(line_num)+":" if line_num else "last line:",
                  *args, file=sys.stderr)
#
# Produces whole passwords from a file, exactly one per line, or from the file's cache
# (which is created by parse_arguments if the file is stdin). These passwords are then
# used by password_generator() as base passwords that can undergo further modifications.
def passwordlist_base_password_generator():
    global initial_passwordlist, passwordlist_warnings

    line_num = 1
    for password_base in initial_passwordlist:  # note that these have already been syntax-checked
        if password_base is not None:           # happens if there was a wildcard syntax error
            yield password_base
        line_num += 1                           # count both valid lines and ones with syntax errors

    if not passwordlist_allcached:
        assert not passwordlist_file.closed
        for line_num, password_base in enumerate(passwordlist_file, line_num):  # not yet syntax-checked
            password_base = password_base.rstrip(mode.tstr("\r\n"))
            try:
                check_chars_range(password_base, "line", no_replacement_chars=True)
            except SystemExit as e:
                passwordlist_warn(line_num, e.code)
                continue
            if args.has_wildcards and b"%" in password_base:
                count_or_error_msg = count_valid_wildcards(password_base, permit_contracting_wildcards=True)
                if isinstance(count_or_error_msg, basestring):
                    passwordlist_warn(line_num, count_or_error_msg)
                    continue
                try:
                    load_backreference_maps_from_token(password_base)
                except IOError as e:
                    passwordlist_warn(line_num, e)
                    continue
            yield password_base

    if passwordlist_warnings:
        if passwordlist_warnings > MAX_PASSWORDLIST_WARNINGS:
            print("\n"+prog+": warning:", passwordlist_warnings-MAX_PASSWORDLIST_WARNINGS,
                  "additional warnings were suppressed", file=sys.stderr)
        passwordlist_warnings = None  # ignore warnings during future runs of the same passwordlist

    # Prepare for a potential future run of the same passwordlist
    if passwordlist_file != sys.stdin:
        passwordlist_file.seek(0)

    # Data from stdin can't be reused if it hasn't been fully cached
    elif not passwordlist_allcached:
        initial_passwordlist = ()
        passwordlist_file.close()


# Produces an infinite number of base passwords for performance measurements. These passwords
# are then used by password_generator() as base passwords that can undergo further modifications.
def default_performance_base_password_generator():
    for i in itertools.count(0):
        yield mode.tstr("Measure Performance ") + mode.tstr(i)


# This generator function expands (or contracts) all wildcards in the string passed
# to it, or if there are no wildcards it simply produces the string unchanged. The
# prior_prefix argument is only used internally while recursing, and is needed to
# support backreference wildcards. The returned value is:
#   prior_prefix + password_with_all_wildcards_expanded
# TODO: implement without recursion?
def expand_wildcards_generator(password_with_wildcards, prior_prefix = None):
    if prior_prefix is None: prior_prefix = mode.tstr()

    # Quick check to see if any wildcards are present
    if mode.tstr("%") not in password_with_wildcards:
        # If none, just produce the string and end
        yield prior_prefix + password_with_wildcards
        return

    # Copy a few globals into local for a small speed boost
    l_xrange = xrange
    l_len    = len
    l_min    = min
    l_max    = max

    # Find the first wildcard parameter in the format %[[min,]max][caseflag]type where
    # caseflag == "i" if present and type is one of: config.wildcard_keys, "<", ">", or "-"
    # (e.g. "%d", "%-", "%2n", "%1,3ia", etc.), or type is of the form "[custom-wildcard-set]", or
    # for backreferences type is of the form: [ ";file;" ["#"] | ";#" ] "b"  <--brackets denote options
    if not config.wildcard_re:
        config.wildcard_re = re.compile(
            br"%(?:(?:(?P<min>\d+),)?(?P<max>\d+))?(?P<nocase>i)?(?:(?P<type>[{}<>-])|\[(?P<custom>.+?)\]|(?:;(?:(?P<bfile>.+?);)?(?P<bpos>\d+)?)?(?P<bref>b))" \
            .format(config.wildcard_keys))
    match = config.wildcard_re.search(password_with_wildcards)
    assert match, "expand_wildcards_generator: parsed valid wildcard spec"

    password_prefix      = password_with_wildcards[0:match.start()]          # no wildcards present here,
    full_password_prefix = prior_prefix + password_prefix                    # nor here;
    password_postfix_with_wildcards = password_with_wildcards[match.end():]  # might be other wildcards in here

    m_bref = match.group(b"bref")
    if m_bref:  # a backreference wildcard, e.g. "%b" or "%;2b" or "%;map.txt;2b"
        m_bfile, m_bpos = match.group(b"bfile", b"bpos")
        m_bpos = int(m_bpos) if m_bpos else 1
        bmap = config.backreference_maps[m_bfile] if m_bfile else None
    else:
        # For positive (expanding) wildcards, build the set of possible characters based on the wildcard type and caseflag
        m_custom, m_nocase = match.group(b"custom", b"nocase")
        if m_custom:  # a custom set wildcard, e.g. %[abcdef0-9]
            is_expanding = True
            wildcard_set = config.custom_wildcard_cache.get((m_custom, m_nocase))
            if wildcard_set is None:
                wildcard_set = build_wildcard_set(m_custom)
                if m_nocase:
                    # Build a case-insensitive version
                    wildcard_set_caseswapped = wildcard_set.swapcase()
                    if wildcard_set_caseswapped != wildcard_set:
                        wildcard_set = duplicates_removed(wildcard_set + wildcard_set_caseswapped)
                config.custom_wildcard_cache[(m_custom, m_nocase)] = wildcard_set
        else:  # either a "normal" or a contracting wildcard
            m_type = match.group(b"type")
            is_expanding = m_type not in b"<>-"
            if is_expanding:
                if m_nocase and m_type in config.wildcard_nocase_sets:
                    wildcard_set = config.wildcard_nocase_sets[m_type]
                else:
                    wildcard_set = config.wildcard_sets[m_type]
        assert not is_expanding or wildcard_set, "expand_wildcards_generator: found expanding wildcard set"

    # Extract or default the wildcard min and max length
    wildcard_maxlen = match.group(b"max")
    wildcard_maxlen = int(wildcard_maxlen) if wildcard_maxlen else 1
    wildcard_minlen = match.group(b"min")
    wildcard_minlen = int(wildcard_minlen) if wildcard_minlen else wildcard_maxlen

    # If it's a backreference wildcard
    if m_bref:
        first_pos = len(full_password_prefix) - m_bpos
        if first_pos < 0:  # if the prefix is shorter than the requested bpos
            wildcard_minlen = l_max(wildcard_minlen + first_pos, 0)
            wildcard_maxlen = l_max(wildcard_maxlen + first_pos, 0)
            m_bpos += first_pos  # will always be >= 1
        m_bpos *= -1             # is now <= -1

        if bmap:  # if it's a backreference wildcard with a map file
            # Special case for when the first password has no wildcard characters appended
            if wildcard_minlen == 0:
                # If the wildcard was at the end of the string, we're done
                if password_postfix_with_wildcards == "":
                    yield full_password_prefix
                # Recurse to expand any additional wildcards possibly in password_postfix_with_wildcards
                else:
                    for password_expanded in expand_wildcards_generator(password_postfix_with_wildcards, full_password_prefix):
                        yield password_expanded

            # Expand the mapping backreference wildcard using the helper function (defined below)
            # (this helper function can't handle the special case above)
            for password_prefix_expanded in expand_mapping_backreference_wildcard(full_password_prefix, wildcard_minlen, wildcard_maxlen, m_bpos, bmap):

                # If the wildcard was at the end of the string, we're done
                if password_postfix_with_wildcards == "":
                    yield password_prefix_expanded
                # Recurse to expand any additional wildcards possibly in password_postfix_with_wildcards
                else:
                    for password_expanded in expand_wildcards_generator(password_postfix_with_wildcards, password_prefix_expanded):
                        yield password_expanded

        else:  # else it's a "normal" backreference wildcard (without a map file)
            # Construct the first password to be produced
            for i in xrange(0, wildcard_minlen):
                full_password_prefix += full_password_prefix[m_bpos]

            # Iterate over the [wildcard_minlen, wildcard_maxlen) range
            i = wildcard_minlen
            while True:

                # If the wildcard was at the end of the string, we're done
                if password_postfix_with_wildcards == "":
                    yield full_password_prefix
                # Recurse to expand any additional wildcards possibly in password_postfix_with_wildcards
                else:
                    for password_expanded in expand_wildcards_generator(password_postfix_with_wildcards, full_password_prefix):
                        yield password_expanded

                i += 1
                if i > wildcard_maxlen: break

                # Construct the next password
                full_password_prefix += full_password_prefix[m_bpos]

    # If it's an expanding wildcard
    elif is_expanding:
        # Iterate through specified wildcard lengths
        for wildcard_len in l_xrange(wildcard_minlen, wildcard_maxlen+1):

            # TODO: go faster
            # Expand the wildcard into a length of characters according to the wildcard type/caseflag
            for wildcard_expanded_list in itertools.product(wildcard_set, repeat=wildcard_len):
                # If the wildcard was at the end of the string, we're done
                if password_postfix_with_wildcards == "":
                    yield full_password_prefix + mode.tstr().join(wildcard_expanded_list)
                    continue
                # Recurse to expand any additional wildcards possibly in password_postfix_with_wildcards
                for password_expanded in expand_wildcards_generator(password_postfix_with_wildcards, full_password_prefix + mode.tstr().join(wildcard_expanded_list)):
                    yield password_expanded

    # Otherwise it's a contracting wildcard
    else:
        # Determine the max # of characters that can be removed from either the left
        # or the right of the wildcard, not yet taking wildcard_maxlen into account
        max_from_left  = l_len(password_prefix) if m_type in b"<-" else 0
        if m_type in b">-":
            max_from_right = password_postfix_with_wildcards.find("%")
            if max_from_right == -1: max_from_right = l_len(password_postfix_with_wildcards)
        else:
            max_from_right = 0

        # Iterate over the total number of characters to remove
        for remove_total in l_xrange(wildcard_minlen, l_min(wildcard_maxlen, max_from_left+max_from_right) + 1):

            # Iterate over the number of characters to remove from the right of the wildcard
            # (this loop runs just once for %#,#< or %#,#> ; or for %#,#- at the beginning or end)
            for remove_right in l_xrange(l_max(0, remove_total-max_from_left), l_min(remove_total, max_from_right) + 1):
                remove_left = remove_total-remove_right

                password_prefix_contracted = full_password_prefix[:-remove_left] if remove_left else full_password_prefix

                # If the wildcard was at the end or if there's nothing remaining on the right, we're done
                if l_len(password_postfix_with_wildcards) - remove_right == 0:
                    yield password_prefix_contracted
                    continue
                # Recurse to expand any additional wildcards possibly in password_postfix_with_wildcards
                for password_expanded in expand_wildcards_generator(password_postfix_with_wildcards[remove_right:], password_prefix_contracted):
                    yield password_expanded


# Recursive helper generator function for expand_wildcards_generator():
#   password_prefix -- the fully expanded password before a %b wildcard
#   minlen, maxlen  -- the min and max from a %#,#b wildcard
#   bpos            -- from a %;#b wildcard, this is -#
#   bmap            -- the dict associated with the file in a %;file;b wildcard
# This function assumes all range checking has already been performed.
def expand_mapping_backreference_wildcard(password_prefix, minlen, maxlen, bpos, bmap):
    for wildcard_expanded in bmap.get(password_prefix[bpos], (password_prefix[bpos],)):
        password_prefix_expanded = password_prefix + wildcard_expanded
        if minlen <= 1:
            yield password_prefix_expanded
        if maxlen > 1:
            for password_expanded in expand_mapping_backreference_wildcard(password_prefix_expanded, minlen-1, maxlen-1, bpos, bmap):
                yield password_expanded


# capslock_typos_generator() is a generator function which tries swapping the case of
# the entire password (producing just one variation of the password_base in addition
# to the password_base itself)
def capslock_typos_generator(password_base, min_typos = 0):
    global typos_sofar

    min_typos -= typos_sofar
    if min_typos > 1: return  # this generator can't ever generate more than 1 typo

    # Start with the unmodified password itself, and end if there's nothing left to do
    if min_typos   <= 0:          yield password_base
    if typos_sofar >= args.typos: return

    password_swapped = password_base.swapcase()
    if password_swapped != password_base:
        typos_sofar += 1
        yield password_swapped
        typos_sofar -= 1


# swap_typos_generator() is a generator function which produces all possible combinations
# of the password_base where zero or more pairs of adjacent characters are swapped. Even
# when multiple swapping typos are requested, any single character is never swapped more
# than once per generated password.
def swap_typos_generator(password_base, min_typos = 0):
    global typos_sofar
    # Copy a few globals into local for a small speed boost
    l_xrange                 = xrange
    l_itertools_combinations = itertools.combinations
    l_args_nodupchecks       = args.no_dupchecks

    # Start with the unmodified password itself
    min_typos -= typos_sofar
    if min_typos <= 0: yield password_base

    # First swap one pair of characters, then all combinations of 2 pairs, then of 3,
    # up to the max requested or up to the max number swappable (whichever's less). The
    # max number swappable is len // 2 because we never swap any single character twice.
    password_base_len = len(password_base)
    max_swaps = min(args.max_typos_swap, args.typos - typos_sofar, password_base_len // 2)
    for swap_count in l_xrange(max(1, min_typos), max_swaps + 1):
        typos_sofar += swap_count

        # Generate all possible combinations of swapping exactly swap_count characters;
        # swap_indexes is a list of indexes of characters that will be swapped in a
        # single guess (swapped with the character at the next position in the string)
        for swap_indexes in l_itertools_combinations(l_xrange(password_base_len-1), swap_count):

            # Look for adjacent indexes in swap_indexes (which would cause a single
            # character to be swapped more than once in a single guess), and only
            # continue if no such adjacent indexes are found
            for i in l_xrange(1, swap_count):
                if swap_indexes[i] - swap_indexes[i-1] == 1:
                    break
            else:  # if we left the loop normally (didn't break)

                # Perform and the actual swaps
                password = password_base
                for i in swap_indexes:
                    if password[i] == password[i+1] and l_args_nodupchecks < 4:  # "swapping" these would result in generating a duplicate guess
                        break
                    password = password[:i] + password[i+1:i+2] + password[i:i+1] + password[i+2:]
                else:  # if we left the loop normally (didn't break)
                    yield password

        typos_sofar -= swap_count

# simple_typos_generator() is a generator function which, given a password_base, produces
# all possible combinations of typos of that password_base, of a count and of types specified
# at the command line. See the Configurables section for a list and description of the
# available simple typo generator types/functions. (The simple_typos_generator() function
# itself isn't very simple... it's called "simple" because the functions in the Configurables
# section which simple_typos_generator() calls are simple; they are collectively called
# simple typo generators)
def simple_typos_generator(password_base, min_typos = 0):
    global typos_sofar
    # Copy a few globals into local for a small speed boost
    l_xrange               = xrange
    l_itertools_product    = itertools.product
    l_product_max_elements = product_max_elements
    l_enabled_simple_typos = enabled_simple_typos
    l_max_simple_typos     = max_simple_typos
    assert len(enabled_simple_typos) > 0, "simple_typos_generator: at least one simple typo enabled"

    # Start with the unmodified password itself
    min_typos -= typos_sofar
    if min_typos <= 0: yield password_base

    # First change all single characters, then all combinations of 2 characters, then of 3, etc.
    password_base_len = len(password_base)
    max_typos         = min(sum_max_simple_typos, args.typos - typos_sofar, password_base_len)
    for typos_count in l_xrange(max(1, min_typos), max_typos + 1):
        typos_sofar += typos_count

        # Pre-calculate all possible permutations of the chosen simple_typos_choices
        # (possibly limited to individual maximums specified by max_simple_typos)
        if l_max_simple_typos:
            simple_typo_permutations = tuple(l_product_max_elements(l_enabled_simple_typos, typos_count, l_max_simple_typos))
        else:  # use the faster itertools version if possible
            simple_typo_permutations = tuple(l_itertools_product(l_enabled_simple_typos, repeat=typos_count))

        # Select the indexes of exactly typos_count characters from the password_base
        # that will be the target of the typos (out of all possible combinations thereof)
        for typo_indexes in itertools.combinations(l_xrange(password_base_len), typos_count):
            # typo_indexes_ has an added sentinel at the end; it's the index of
            # one-past-the-end of password_base. This is used in the inner loop.
            typo_indexes_ = typo_indexes + (password_base_len,)

            # Apply each possible permutation of simple typo generators to
            # the typo targets selected above (using the pre-calculated list)
            for typo_generators_per_target in simple_typo_permutations:

                # For each of the selected typo target(s), call the generator(s) selected above
                # to get the replacement(s) of said to-be-replaced typo target(s). Each item in
                # typo_replacements is an iterable (tuple, list, generator, etc.) producing
                # zero or more replacements for a single target. If there are zero replacements
                # for any target, the for loop below intentionally produces no results at all.
                typo_replacements = [ generator(password_base, index) for index, generator in
                    zip(typo_indexes, typo_generators_per_target) ]

                # one_replacement_set is a tuple of exactly typos_count length, with one
                # replacement per selected typo target. If all of the selected generators
                # above each produce only one replacement, this loop will execute once with
                # that one replacement set. If one or more of the generators produce multiple
                # replacements (for a single target), this loop iterates across all possible
                # combinations of those replacements. If any generator produces zero outputs
                # (therefore that the target has no typo), this loop iterates zero times.
                for one_replacement_set in l_itertools_product(*typo_replacements):

                    # Construct a new password, left-to-right, from password_base and the
                    # one_replacement_set. (Note the use of typo_indexes_, not typo_indexes.)
                    password = password_base[0:typo_indexes_[0]]
                    for i, replacement in enumerate(one_replacement_set):
                        password += replacement + password_base[typo_indexes_[i]+1:typo_indexes_[i+1]]
                    yield password

        typos_sofar -= typos_count

# product_max_elements() is a generator function similar to itertools.product() except that
# it takes an extra argument:
#     max_elements  -  a list of length == len(sequence) of positive (non-zero) integers
# When min(max_elements) >= r, these two calls are equivalent:
#     itertools.product(sequence, repeat=r)
#     product_max_elements(sequence, r, max_elements)
# When one of the integers in max_elements < r, then the corresponding element of sequence
# is never repeated in any single generated output more than the requested number of times.
# For example:
#     tuple(product_max_elements(['a', 'b'], 3, [1, 2]))  ==
#     (('a', 'b', 'b'), ('b', 'a', 'b'), ('b', 'b', 'a'))
# Just like itertools.product, each output generated is of length r. Note that if
# sum(max_elements) < r, then zero outputs are (inefficiently) produced.
def product_max_elements(sequence, repeat, max_elements):
    if repeat == 1:
        for choice in sequence:
            yield (choice,)
        return

    # If all of the max_elements are >= repeat, just use the faster itertools version
    if min(max_elements) >= repeat:
        for product in itertools.product(sequence, repeat=repeat):
            yield product
        return

    # Iterate through the elements to choose one for the first position
    for i, choice in enumerate(sequence):

        # If this is the last time this element can be used, remove it from the sequence when recursing
        if max_elements[i] == 1:
            for rest in product_max_elements(sequence[:i] + sequence[i+1:], repeat - 1, max_elements[:i] + max_elements[i+1:]):
                yield (choice,) + rest

        # Otherwise, just reduce it's allowed count before recursing to generate the rest of the result
        else:
            max_elements[i] -= 1
            for rest in product_max_elements(sequence, repeat - 1, max_elements):
                yield (choice,) + rest
            max_elements[i] += 1


# insert_typos_generator() is a generator function which inserts one or more strings
# from the typos_insert_expanded list between every pair of characters in password_base,
# as well as at its beginning and its end.
def insert_typos_generator(password_base, min_typos = 0):
    global typos_sofar
    # Copy a few globals into local for a small speed boost
    l_max_adjacent_inserts = args.max_adjacent_inserts
    l_xrange               = xrange
    l_itertools_product    = itertools.product

    # Start with the unmodified password itself
    min_typos -= typos_sofar
    if min_typos <= 0: yield password_base

    password_base_len = len(password_base)
    assert l_max_adjacent_inserts > 0
    if l_max_adjacent_inserts > 1:
        # Can select for insertion the same index more than once in a single guess
        combinations_function = itertools.combinations_with_replacement
        max_inserts = min(args.max_typos_insert, args.typos - typos_sofar)
    else:
        # Will select for insertion an index at most once in a single guess
        combinations_function = itertools.combinations
        max_inserts = min(args.max_typos_insert, args.typos - typos_sofar, password_base_len + 1)

    # First insert a single string, then all combinations of 2 strings, then of 3, etc.
    for inserts_count in l_xrange(max(1, min_typos), max_inserts + 1):
        typos_sofar += inserts_count

        # Select the indexes (some possibly the same) of exactly inserts_count characters
        # from the password_base before which new string(s) will be inserted
        for insert_indexes in combinations_function(l_xrange(password_base_len + 1), inserts_count):

            # If multiple inserts are permitted at a single location, make sure they're
            # limited to args.max_adjacent_inserts. (If multiple inserts are not permitted,
            # they are never produced by the combinations_function selected earlier.)
            if l_max_adjacent_inserts > 1 and inserts_count > l_max_adjacent_inserts:
                too_many_adjacent = False
                last_index = -1
                for index in insert_indexes:
                    if index != last_index:
                        adjacent_count = 1
                        last_index = index
                    else:
                        adjacent_count += 1
                        too_many_adjacent = adjacent_count > l_max_adjacent_inserts
                        if too_many_adjacent: break
                if too_many_adjacent: continue

            # insert_indexes_ has an added sentinel at the end; it's the index of
            # one-past-the-end of password_base. This is used in the inner loop.
            insert_indexes_ = insert_indexes + (password_base_len,)

            # For each of the selected insert indexes, select a replacement from
            # typos_insert_expanded (which is created in parse_arguments() )
            for one_insertion_set in l_itertools_product(typos_insert_expanded, repeat = inserts_count):

                # Construct a new password, left-to-right, from password_base and the
                # one_insertion_set. (Note the use of insert_indexes_, not insert_indexes.)
                password = password_base[0:insert_indexes_[0]]
                for i, insertion in enumerate(one_insertion_set):
                    password += insertion + password_base[insert_indexes_[i]:insert_indexes_[i+1]]
                yield password

        typos_sofar -= inserts_count


################################### Main ###################################


# Simply forwards calls on to the return_verified_password_or_false()
# member function of the currently loaded global wallet
def return_verified_password_or_false(passwords):
    return Wallet.get_loaded_wallet().return_verified_password_or_false(passwords)


# Init function for the password verifying worker processes:
#   (re-)loads the wallet & mode (should only be necessary on Windows),
#   tries to set the process priority to minimum, and
#   begins ignoring SIGINTs for a more graceful exit on Ctrl-C
# loaded_wallet = None  # initialized once at global scope for Windows
def init_worker(wallet, char_mode):
    if not Wallet.get_loaded_wallet():
        Wallet.set_loaded_wallet(wallet)
        if char_mode == str:
            mode.enable_ascii_mode()
        elif char_mode == unicode:
            mode.enable_unicode_mode()
        else:
            assert False
    set_process_priority_idle()
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def set_process_priority_idle():
    try:
        if sys.platform == "win32":
            import ctypes, ctypes.wintypes
            GetCurrentProcess = ctypes.windll.kernel32.GetCurrentProcess
            GetCurrentProcess.argtypes = ()
            GetCurrentProcess.restype  = ctypes.wintypes.HANDLE
            SetPriorityClass = ctypes.windll.kernel32.SetPriorityClass
            SetPriorityClass.argtypes = ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD
            SetPriorityClass.restype  = ctypes.wintypes.BOOL
            SetPriorityClass(GetCurrentProcess(), 0x00000040)  # IDLE_PRIORITY_CLASS
        else:
            os.nice(19)
    except StandardError: pass

# If an out-of-memory error occurs which can be handled, free up some memory, display
# an informative error message, and then return True, otherwise return False.
# Generally a call to handle_oom() should be followed by a sys.exit(1)
def handle_oom():
    global password_dups, token_combination_dups  # these are the memory-hogging culprits
    if password_dups and password_dups._run_number == 0:
        del password_dups, token_combination_dups
        gc.collect()
        print()  # move to the next line
        print(prog+": error: out of memory", file=sys.stderr)
        print(prog+": notice: the --no-dupchecks option will reduce memory usage at the possible expense of speed", file=sys.stderr)
        return True
    elif token_combination_dups and token_combination_dups._run_number == 0:
        del token_combination_dups
        gc.collect()
        print()  # move to the next line
        print(prog+": error: out of memory", file=sys.stderr)
        print(prog+": notice: the --no-dupchecks option can be specified twice to further reduce memory usage", file=sys.stderr)
        return True
    return False


# Saves progress by overwriting the older (of two) slots in the autosave file
# (autosave_nextslot is initialized in load_savestate() or parse_arguments() )
def do_autosave(skip, inside_interrupt_handler = False):
    global autosave_nextslot
    assert autosave_file and not autosave_file.closed,           "do_autosave: autosave_file is open"
    assert isinstance(savestate, dict) and b"argv" in savestate, "do_autosave: savestate is initialized"
    if not inside_interrupt_handler:
        sigint_handler  = signal.signal(signal.SIGINT,  signal.SIG_IGN)    # ignore Ctrl-C,
        sigterm_handler = signal.signal(signal.SIGTERM, signal.SIG_IGN)    # SIGTERM, and
        if sys.platform != "win32":  # (windows has no SIGHUP)
            sighup_handler = signal.signal(signal.SIGHUP, signal.SIG_IGN)  # SIGHUP while saving
    # Erase the target save slot so that a partially written save will be recognized as such
    if autosave_nextslot == 0:
        start_pos = 0
        autosave_file.seek(start_pos)
        autosave_file.write(SAVESLOT_SIZE * b"\0")
        autosave_file.flush()
        try:   os.fsync(autosave_file.fileno())
        except StandardError: pass
        autosave_file.seek(start_pos)
    else:
        assert autosave_nextslot == 1
        start_pos = SAVESLOT_SIZE
        autosave_file.seek(start_pos)
        autosave_file.truncate()
        try:   os.fsync(autosave_file.fileno())
        except StandardError: pass
    savestate[b"skip"] = skip  # overwrite the one item which changes for each autosave
    cPickle.dump(savestate, autosave_file, cPickle.HIGHEST_PROTOCOL)
    assert autosave_file.tell() <= start_pos + SAVESLOT_SIZE, "do_autosave: data <= "+unicode(SAVESLOT_SIZE)+" bytes long"
    autosave_file.flush()
    try:   os.fsync(autosave_file.fileno())
    except StandardError: pass
    autosave_nextslot = 1 if autosave_nextslot==0 else 0
    if not inside_interrupt_handler:
        signal.signal(signal.SIGINT,  sigint_handler)
        signal.signal(signal.SIGTERM, sigterm_handler)
        if sys.platform != "win32":
            signal.signal(signal.SIGHUP, sighup_handler)


# Given an est_secs_per_password, counts the *total* number of passwords generated by password_generator()
# (including those skipped by args.skip), and returns the result, checking the --max-eta constraint along
# the way (and exiting if it's violated). Displays messages to the user if the process is taking a while.
def count_and_check_eta(est):
    assert est > 0.0, "count_and_check_eta: est_secs_per_password > 0.0"
    return password_generator_factory(est_secs_per_password=est)[1]


# Creates a password iterator from the chosen password_generator() and advances it past skipped passwords (as
# per args.skip), returning a tuple: new_iterator, #_of_passwords_skipped. Displays messages to the user if the
# process is taking a while. (Or does the work of count_and_check_eta() when passed est_secs_per_password.)
SECONDS_BEFORE_DISPLAY    = 5.0
PASSWORDS_BETWEEN_UPDATES = 100000
def password_generator_factory(chunksize = 1, est_secs_per_password = 0):
    # If est_secs_per_password is zero, only skipping is performed;
    # if est_secs_per_password is non-zero, all passwords (including skipped ones) are counted.

    print("password_generator_factory(): chunksize:", chunksize)

    # If not counting all passwords (if only skipping)
    if not est_secs_per_password:
        # The simple case where there's nothing to skip, just return an unmodified password_generator()
        if args.skip <= 0:
            return password_generator(chunksize), 0
        # The still fairly simple case where there's not much to skip, just skip it all at once
        elif args.skip <= PASSWORDS_BETWEEN_UPDATES:
            passwords_count_iterator = password_generator(args.skip, only_yield_count=True)
            passwords_counted = 0
            try:
                # Skip it all in a single iteration (or raise StopIteration if it's empty)
                passwords_counted = passwords_count_iterator.next()
                passwords_count_iterator.send( (chunksize, False) )  # change it into a "normal" iterator
            except StopIteration: pass
            return passwords_count_iterator, passwords_counted

    assert args.skip >= 0
    sys_stderr_isatty = sys.stderr.isatty()
    max_seconds = args.max_eta * 3600  # max_eta is in hours
    passwords_count_iterator = password_generator(PASSWORDS_BETWEEN_UPDATES, only_yield_count=True)
    passwords_counted = 0
    is_displayed = False
    start = time.clock() if sys_stderr_isatty else None
    try:
        # Iterate though the password counts in increments of size PASSWORDS_BETWEEN_UPDATES
        for passwords_counted_last in passwords_count_iterator:
            # print("password_generator_factory(): got a chunk")
            passwords_counted += passwords_counted_last
            unskipped_passwords_counted = passwords_counted - args.skip

            # If it's taking a while, and if we're not almost done, display/update the on-screen message

            if not is_displayed and sys_stderr_isatty and time.clock() - start > SECONDS_BEFORE_DISPLAY and (
                    est_secs_per_password or passwords_counted * 1.5 < args.skip):
                print("Counting passwords ..." if est_secs_per_password else "Skipping passwords ...", file=sys.stderr)
                is_displayed = True

            if is_displayed:
                # If ETAs were requested, calculate and possibly display one
                if est_secs_per_password:
                    # Only display an ETA once unskipped passwords are being counted
                    if unskipped_passwords_counted > 0:
                        eta = unskipped_passwords_counted * est_secs_per_password / 60
                        if eta < 90:     eta = unicode(int(eta)+1) + " minutes"  # round up
                        else:
                            eta /= 60
                            if eta < 48: eta = unicode(int(round(eta))) + " hours"
                            else:        eta = unicode(round(eta / 24, 1)) + " days"
                        msg = "\r  {:,}".format(passwords_counted)
                        if args.skip: msg += " (includes {:,} skipped)".format(args.skip)
                        msg += "  ETA: " + eta + " and counting   "
                        print(msg, end="", file=sys.stderr)
                    # Else just indicate that all the passwords counted so far are skipped
                    else:
                        print("\r  {:,} (all skipped)".format(passwords_counted), end="", file=sys.stderr)
                #
                # Else no ETAs were requested, just display the count ("Skipping passwords ..." was already printed)
                else:
                    print("\r  {:,}".format(passwords_counted), end="", file=sys.stderr)

            # If the ETA is past its max permitted limit, exit
            if unskipped_passwords_counted * est_secs_per_password > max_seconds:
                error_exit("\rat least {:,} passwords to try, ETA > --max-eta option ({} hours), exiting" \
                    .format(passwords_counted - args.skip, args.max_eta))

            # If not counting all the passwords, then break out of this loop before it's gone past args.skip
            # (actually it must leave at least one password left to count before the args.skip limit)
            if not est_secs_per_password and passwords_counted >= args.skip - PASSWORDS_BETWEEN_UPDATES:
                break

        # Erase the on-screen counter if it was being displayed
        if is_displayed:
            print("\rDone" + " "*74, file=sys.stderr)

        # If all passwords were being/have been counted
        if est_secs_per_password:
            return None, passwords_counted

        # Else finish counting the final (probably partial) iteration of skipped passwords
        # (which will be in the range [1, PASSWORDS_BETWEEN_UPDATES] )
        else:
            try:
                passwords_count_iterator.send( (args.skip - passwords_counted, True) )  # the remaining count
                passwords_counted += passwords_count_iterator.next()
                passwords_count_iterator.send( (chunksize, False) )  # change it into a "normal" iterator
            except StopIteration: pass
            return passwords_count_iterator, passwords_counted

    except SystemExit: raise  # happens when error_exit is called above
    except BaseException as e:
        handled = handle_oom() if isinstance(e, MemoryError) and passwords_counted > 0 else False
        if not handled: print(file=sys.stderr)  # move to the next line if handle_oom() hasn't already done so

        counting_or_skipping = "counting" if est_secs_per_password else "skipping"
        including_skipped    = "(including skipped ones)" if est_secs_per_password and args.skip else ""
        print("Interrupted after", counting_or_skipping, passwords_counted, "passwords", including_skipped, file=sys.stderr)

        if handled:                          sys.exit(1)
        if isinstance(e, KeyboardInterrupt): sys.exit(0)
        raise


# Should be called after calling parse_arguments()
# Returns a two-element tuple:
#   the first element is the password, if found, otherwise False;
#   the second is a human-readable result iff no password was found; or
#   returns (None, None) for abnormal but not fatal errors (e.g. Ctrl-C)
def main():

    start_time = time.time()

    # Once installed, performs cleanup prior to a requested process shutdown on Windows
    # (this is defined inside main so it can access the passwords_tried local)
    def windows_ctrl_handler(signal):
        if signal == 0:   # if it's a Ctrl-C,
           return False   # defer to the native Python handler which works just fine
        #
        # Python on Windows is a bit touchy with signal handlers; it's safest to just do
        # all the cleanup code here (even though it'd be cleaner to throw an exception)
        if savestate:
            do_autosave(args.skip + passwords_tried, inside_interrupt_handler=True)  # do this first, it's most important
            autosave_file.close()
        print("\nInterrupted after finishing password #", args.skip + passwords_tried, file=sys.stderr)
        if sys.stdout.isatty() ^ sys.stderr.isatty():  # if they're different, print to both to be safe
            print("\nInterrupted after finishing password #", args.skip + passwords_tried)
        os._exit(1)

    # Copy a global into local for a small speed boost
    l_savestate = savestate

    # If --listpass was requested, just list out all the passwords and exit
    passwords_count = 0
    if args.listpass:
        if mode.tstr == unicode:
            stdout_encoding = sys.stdout.encoding if hasattr(sys.stdout, "encoding") else None  # for unittest
            if not stdout_encoding:
                print(prog+": warning: output will be UTF-8 encoded", file=sys.stderr)
                stdout_encoding = "utf_8"
            elif "UTF" in stdout_encoding.upper():
                stdout_encoding = None  # let the builtin print do the encoding automatically
            else:
                print(prog+": warning: stdout's encoding is not Unicode compatible; data loss may occur", file=sys.stderr)
        else:
            stdout_encoding = None
        password_iterator, skipped_count = password_generator_factory()
        plus_skipped = " (plus " + unicode(skipped_count) + " skipped)" if skipped_count else ""
        try:
            for password in password_iterator:
                passwords_count += 1
                builtin_print(password[0] if stdout_encoding is None else password[0].encode(stdout_encoding, "replace"))
        except BaseException as e:
            handled = handle_oom() if isinstance(e, MemoryError) and passwords_count > 0 else False
            if not handled: print()  # move to the next line
            print("Interrupted after generating", passwords_count, "passwords" + plus_skipped, file=sys.stderr)
            if handled:                          sys.exit(1)
            if isinstance(e, KeyboardInterrupt): sys.exit(0)
            raise
        return None, unicode(passwords_count) + " password combinations" + plus_skipped

    try:
        print("Wallet difficulty:", Wallet.get_loaded_wallet().difficulty_info())
    except AttributeError: pass

    # Measure the performance of the verification function
    # (for CPU, run for about 0.5s; for GPU, run for one global-worksize chunk)
    if args.performance and args.enable_gpu:  # skip this time-consuming & unnecessary measurement in this case
        est_secs_per_password = 0.01          # set this to something relatively big, it doesn't matter exactly what
    else:
        if args.enable_gpu:
            inner_iterations = sum(args.global_ws)
            outer_iterations = 1
        else:
            # Passwords are verified in "chunks" to reduce call overhead. One chunk includes enough passwords to
            # last for about 1/100th of a second (determined experimentally to be about the best I could do, YMMV)
            CHUNKSIZE_SECONDS = 1.0 / 100.0
            measure_performance_iterations = Wallet.get_loaded_wallet().passwords_per_seconds(0.5)
            inner_iterations = int(round(2*measure_performance_iterations * CHUNKSIZE_SECONDS)) or 1  # the "2*" is due to the 0.5 seconds above
            outer_iterations = int(round(measure_performance_iterations / inner_iterations))
            assert outer_iterations > 0
        #
        performance_generator = performance_base_password_generator()  # generates dummy passwords
        start = timeit.default_timer()
        # Emulate calling the verification function with lists of size inner_iterations
        for o in xrange(outer_iterations):
            Wallet.get_loaded_wallet().return_verified_password_or_false(list(
                itertools.islice(itertools.ifilter(custom_final_checker, performance_generator), inner_iterations)))
        est_secs_per_password = (timeit.default_timer() - start) / (outer_iterations * inner_iterations)
        del performance_generator
        assert isinstance(est_secs_per_password, float) and est_secs_per_password > 0.0

    if args.enable_gpu:
        chunksize = sum(args.global_ws)
    else:
        # (see CHUNKSIZE_SECONDS above)
        chunksize = int(round(CHUNKSIZE_SECONDS / est_secs_per_password)) or 1

    # If the time to verify a password is short enough, the time to generate the passwords in this thread
    # becomes comparable to verifying passwords, therefore this should count towards being a "worker" thread
    if est_secs_per_password < 1.0 / 75000.0:
        main_thread_is_worker = True
        spawned_threads   = args.threads - 1      # spawn 1 fewer than requested (might be 0)
        verifying_threads = spawned_threads or 1
    else:
        main_thread_is_worker = False
        spawned_threads   = args.threads if args.threads > 1 else 0
        verifying_threads = args.threads

    # Adjust estimate for the number of verifying threads (final estimate is probably an underestimate)
    est_secs_per_password /= min(verifying_threads, cpus)

    # Count how many passwords there are (excluding skipped ones) so we can display and conform to ETAs
    if not args.no_eta:

        assert args.skip >= 0
        if l_savestate and b"total_passwords" in l_savestate and args.no_dupchecks:
            passwords_count = l_savestate[b"total_passwords"]  # we don't need to do a recount
            iterate_time = 0
        else:
            start = time.clock()
            passwords_count = count_and_check_eta(est_secs_per_password)
            iterate_time = time.clock() - start
            if l_savestate:
                if b"total_passwords" in l_savestate:
                    assert l_savestate[b"total_passwords"] == passwords_count, "main: saved password count matches actual count"
                else:
                    l_savestate[b"total_passwords"] = passwords_count

        passwords_count -= args.skip
        if passwords_count <= 0:
            return False, "Skipped all "+unicode(passwords_count + args.skip)+" passwords, exiting"

        # If additional ETA calculations are required
        if l_savestate or not have_progress:
            eta_seconds = passwords_count * est_secs_per_password
            # if the main thread is sharing CPU time with a verifying thread
            if spawned_threads == 0 and not args.enable_gpu or spawned_threads >= cpus:
                eta_seconds += iterate_time
            if l_savestate:
                est_passwords_per_5min = int(round(passwords_count / eta_seconds * 300.0))
                assert est_passwords_per_5min > 0
            eta_seconds = int(round(eta_seconds)) or 1

    # else if args.no_eta and savestate, calculate a simple approximate of est_passwords_per_5min
    elif l_savestate:
        est_passwords_per_5min = int(round(300.0 / est_secs_per_password))
        assert est_passwords_per_5min > 0

    # If there aren't many passwords, give each of the N workers 1/Nth of the passwords
    # (rounding up) and also don't bother spawning more threads than there are passwords
    if not args.no_eta and spawned_threads * chunksize > passwords_count:
        if spawned_threads > passwords_count:
            spawned_threads = passwords_count
        chunksize = (passwords_count-1) // spawned_threads + 1

    # Create an iterator which produces the password permutations in chunks, skipping some if so instructed
    if args.skip > 0:
        print("Starting with password #", args.skip + 1)

    password_iterator, skipped_count = password_generator_factory(chunksize)

    if skipped_count < args.skip:
        assert args.no_eta, "discovering all passwords have been skipped this late only happens if --no-eta"
        return False, "Skipped all " +unicode(skipped_count)+" passwords, exiting"
    assert skipped_count == args.skip

    if args.enable_gpu:
        cl_devices = Wallet.get_loaded_wallet()._cl_devices
        if len(cl_devices) == 1:
            print("Using OpenCL", pyopencl.device_type.to_string(cl_devices[0].type), cl_devices[0].name.strip())
        else:
            print("Using", len(cl_devices), "OpenCL devices:")
            for dev in cl_devices:
                print(" ", pyopencl.device_type.to_string(dev.type), dev.name.strip())
    else:
        print("Using", args.threads, "worker", "threads" if args.threads > 1 else "thread")  # (they're actually worker processes)

    if have_progress:
        if args.no_eta:
            progress = progressbar.ProgressBar(maxval=progressbar.UnknownLength, poll=0.1, widgets=[
                progressbar.AnimatedMarker(),
                progressbar.FormatLabel(b" %(value)d  elapsed: %(elapsed)s  rate: "),
                progressbar.FileTransferSpeed(unit=b"P")
            ])
            progress.update_interval = sys.maxint  # work around performance bug in ProgressBar
        else:
            progress = progressbar.ProgressBar(maxval=passwords_count, poll=0.1, widgets=[
                progressbar.SimpleProgress(), b" ",
                progressbar.Bar(left=b"[", fill=b"-", right=b"]"),
                progressbar.FormatLabel(b" %(elapsed)s, "),
                progressbar.ETA()
            ])
    else:
        progress = None
        if args.no_eta:
            print("Searching for password ...")
        else:
            # If progressbar is unavailable, print out a time estimate instead
            print("Will try {:,} passwords, ETA ".format(passwords_count), end="")
            eta_hours    = eta_seconds // 3600
            eta_seconds -= 3600 * eta_hours
            eta_minutes  = eta_seconds // 60
            eta_seconds -= 60 * eta_minutes
            if eta_hours   > 0: print(eta_hours,   "hours ",   end="")
            if eta_minutes > 0: print(eta_minutes, "minutes ", end="")
            if eta_hours  == 0: print(eta_seconds, "seconds ", end="")
            print("...")

    # Autosave the starting state now that we're just about ready to start
    if l_savestate: do_autosave(args.skip)

    # Try to release as much memory as possible (before forking if multiple workers are being used)
    # (the initial counting process can be memory intensive)
    gc.collect()

    # Create an iterator which actually checks the (remaining) passwords produced by the password_iterator
    # by executing the return_verified_password_or_false worker function in possibly multiple threads
    if spawned_threads == 0:
        pool = None
        password_found_iterator = itertools.imap(return_verified_password_or_false, password_iterator)
        set_process_priority_idle()  # this, the only thread, should be nice
    else:
        pool = multiprocessing.Pool(spawned_threads, init_worker, (Wallet.get_loaded_wallet(), mode.tstr))
        password_found_iterator = pool.imap(return_verified_password_or_false, password_iterator, 10)
        if main_thread_is_worker: set_process_priority_idle()  # if this thread is cpu-intensive, be nice

    # Try to catch all types of intentional program shutdowns so we can
    # display password progress information and do a final autosave
    windows_handler_routine = None
    try:
        sigint_handler = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGTERM, sigint_handler)     # OK to call on any OS
        if sys.platform != "win32":
            signal.signal(signal.SIGHUP, sigint_handler)  # can't call this on windows
        else:
            import ctypes, ctypes.wintypes
            HandlerRoutine = ctypes.WINFUNCTYPE(ctypes.wintypes.BOOL, ctypes.wintypes.DWORD)
            SetConsoleCtrlHandler = ctypes.windll.kernel32.SetConsoleCtrlHandler
            SetConsoleCtrlHandler.argtypes = HandlerRoutine, ctypes.wintypes.BOOL
            SetConsoleCtrlHandler.restype  = ctypes.wintypes.BOOL
            windows_handler_routine = HandlerRoutine(windows_ctrl_handler)  # creates a C callback from the Python function
            SetConsoleCtrlHandler(windows_handler_routine, True)
    except StandardError: pass

    # Make est_passwords_per_5min evenly divisible by chunksize
    # (so that passwords_tried % est_passwords_per_5min will eventually == 0)
    if l_savestate:
        assert isinstance(est_passwords_per_5min, numbers.Integral)
        assert isinstance(chunksize,              numbers.Integral)
        est_passwords_per_5min = (est_passwords_per_5min // chunksize or 1) * chunksize

    # Iterate through password_found_iterator looking for a successful guess
    password_found  = False
    passwords_tried = 0
    if progress: progress.start()
    try:
        for password_found, passwords_tried_last in password_found_iterator:
            if password_found:
                if pool:
                    # Close the pool, but don't wait for (join) processes to exit gracefully on
                    # the off chance one is in an inconsistent state (otherwise the found password
                    # may never be printed). We also don't want pool to be garbage-collected when
                    # main() returns (it can cause confusing warnings), so keep a reference to it.
                    pool.close()
                    global _pool
                    _pool = pool
                passwords_tried += passwords_tried_last - 1  # just before the found password
                if progress:
                    progress.next_update = 0  # force a screen update
                    progress.update(passwords_tried)
                    print()  # move down to the line below the progress bar
                break
            passwords_tried += passwords_tried_last
            if progress: progress.update(passwords_tried)
            if l_savestate and passwords_tried % est_passwords_per_5min == 0:
                do_autosave(args.skip + passwords_tried)
        else:  # if the for loop exits normally (without breaking)
            if pool: pool.close()
            if progress:
                if args.no_eta:
                    progress.maxval = passwords_tried
                else:
                    progress.widgets.pop()  # remove the ETA
                progress.finish()
            if pool: pool.join()  # if not found, waiting for processes to exit gracefully isn't a problem

    # Gracefully handle any exceptions, printing the count completed so far so that it can be
    # skipped if the user restarts the same run. If the exception was expected (Ctrl-C or some
    # other intentional shutdown, or an out-of-memory condition that can be handled), fall
    # through to the autosave, otherwise re-raise the exception.
    except BaseException as e:
        handled = handle_oom() if isinstance(e, MemoryError) and passwords_tried > 0 else False
        if not handled: print()  # move to the next line if handle_oom() hasn't already done so
        if pool: pool.close()

        print("Interrupted after finishing password #", args.skip + passwords_tried, file=sys.stderr)
        if sys.stdout.isatty() ^ sys.stderr.isatty():  # if they're different, print to both to be safe
            print("Interrupted after finishing password #", args.skip + passwords_tried)

        if not handled and not isinstance(e, KeyboardInterrupt): raise
        password_found = None  # neither False nor True -- unknown
    finally:
        if windows_handler_routine:
            SetConsoleCtrlHandler(windows_handler_routine, False)

    # Autosave the final state (for all non-error cases -- we're shutting down (e.g. Ctrl-C or a
    # reboot), the password was found, or the search was exhausted -- or for handled out-of-memory)
    if l_savestate:
        do_autosave(args.skip + passwords_tried)
        autosave_file.close()

    stop_time = time.time()

    print("{:2f} seconds elapsed".format(stop_time - start_time))


    return (password_found, "Password search exhausted" if password_found is False else None)
