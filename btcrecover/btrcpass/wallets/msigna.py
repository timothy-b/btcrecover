from __future__ import print_function

import hashlib
import itertools
import struct
import sys

from btcrecover.btrcpass.wallets.wallet import Wallet
from btcrecover.utilities.crypto_util import CryptoUtil
from btcrecover.btrcpass import mode
from btcrecover.utilities.safe_print import error_exit


@Wallet.register_wallet_class
class WalletMsigna(object):

    class __metaclass__(type):
        @property
        def data_extract_id(cls): return b"ms"

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        # returns "maybe yes" or "definitely no" (Bither wallets are also SQLite 3)
        return None if wallet_file.read(16) == b"SQLite format 3\0" else False

    def __init__(self, loading=False, msigna_keychain=None):
        assert loading, 'use load_from_* to create a ' + self.__class__.__name__
        aes_library_name = CryptoUtil.load_aes256_library().__name__
        self._passwords_per_second = 50000 if aes_library_name == "Crypto" else 5000

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        CryptoUtil.load_aes256_library(warnings=False)
        self.__dict__ = state

    def passwords_per_seconds(self, seconds):
        return max(int(round(self._passwords_per_second * seconds)), 1)

    # Load an encrypted privkey and salt from the specified keychain given a filename of an mSIGNA vault
    @classmethod
    def load_from_filename(cls, wallet_filename, settings=None):
        # Find the one keychain to test passwords against or exit trying
        import sqlite3
        wallet_conn = sqlite3.connect(wallet_filename)
        wallet_conn.row_factory = sqlite3.Row
        select = b"SELECT * FROM Keychain"
        try:
            if "args" in globals() and settings.msigna_keychain:  # args is not defined during unit tests
                wallet_cur = wallet_conn.execute(select + b" WHERE name LIKE '%' || ? || '%'", (settings.msigna_keychain,))
            else:
                wallet_cur = wallet_conn.execute(select)
        except sqlite3.OperationalError as e:
            if str(e).startswith(b"no such table"):
                raise ValueError("Not an mSIGNA wallet: " + unicode(e))  # it might be a Bither wallet
            else:
                raise  # unexpected error
        keychain = wallet_cur.fetchone()
        if not keychain:
            error_exit("no such keychain found in the mSIGNA vault")
        keychain_extra = wallet_cur.fetchone()
        if keychain_extra:
            print("Multiple matching keychains found in the mSIGNA vault:", file=sys.stderr)
            print("  ", keychain[b"name"])
            print("  ", keychain_extra[b"name"])
            for keychain_extra in wallet_cur:
                print("  ", keychain_extra[b"name"])
            error_exit("use --msigna-keychain NAME to specify a specific keychain")
        wallet_conn.close()

        privkey_ciphertext = str(keychain[b"privkey_ciphertext"])
        if len(privkey_ciphertext) == 32:
            error_exit("mSIGNA keychain '"+keychain[b"name"]+"' is not encrypted")
        if len(privkey_ciphertext) != 48:
            error_exit("mSIGNA keychain '"+keychain[b"name"]+"' has an unexpected privkey length")

        # only need the final 2 encrypted blocks (half of which is padding) plus the salt
        self = cls(loading=True)
        self._part_encrypted_privkey = privkey_ciphertext[-32:]
        self._salt                   = struct.pack(b"< q", keychain[b"privkey_salt"])
        return self

    # Import an encrypted privkey and salt that was extracted by extract-msigna-privkey.py
    @classmethod
    def load_from_data_extract(cls, privkey_data):
        self = cls(loading=True)
        self._part_encrypted_privkey = privkey_data[:32]
        self._salt                   = privkey_data[32:]
        return self

    def difficulty_info(self):
        return "2 SHA-256 iterations"

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def return_verified_password_or_false(self, passwords):
        # Copy some vars into local for a small speed boost
        l_sha1                 = hashlib.sha1
        l_sha256               = hashlib.sha256
        part_encrypted_privkey = self._part_encrypted_privkey
        salt                   = self._salt

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        if mode.tstr == unicode:
            passwords = itertools.imap(lambda p: p.encode("utf_8", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):
            password_hashed = l_sha256(l_sha256(password).digest()).digest()  # mSIGNA does this first
            #
            # mSIGNA's remaining KDF is OpenSSL's EVP_BytesToKey using SHA1 and an iteration count of
            # 5. The EVP_BytesToKey outer loop is unrolled with two iterations below which produces
            # 320 bits (2x SHA1's output) which is > 32 bytes (what's needed for the AES-256 key)
            derived_part1 = password_hashed + salt
            for i in xrange(5):  # 5 is mSIGNA's hard coded iteration count
                derived_part1 = l_sha1(derived_part1).digest()
            derived_part2 = derived_part1 + password_hashed + salt
            for i in xrange(5):
                derived_part2 = l_sha1(derived_part2).digest()
            #
            part_privkey = CryptoUtil.aes256_cbc_decrypt(derived_part1 + derived_part2[:12], part_encrypted_privkey[:16], part_encrypted_privkey[16:])
            #
            # If the last block (bytes 16-31) of part_encrypted_privkey is all padding, we've found it
            if part_privkey == b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10":
                return password if mode.tstr == str else password.decode("utf_8", "replace"), count

        return False, count