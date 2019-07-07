from __future__ import print_function

import base64
import hashlib
import itertools
import os
import sys

from btcrecover.btrcpass.wallets.wallet import Wallet
from btcrecover.btrcpass import mode
from btcrecover.utilities.crypto_util import CryptoUtil


############### MultiBit ###############
# - MultiBit .key backup files
# - MultiDoge .key backup files
# - Bitcoin Wallet for Android/BlackBerry v3.47+ wallet backup files
# - Bitcoin Wallet for Android/BlackBerry v2.24 and older key backup files
# - Bitcoin Wallet for Android/BlackBerry v2.3 - v3.46 key backup files
# - KnC for Android key backup files (same as the above)


@Wallet.register_wallet_class
class WalletMultiBit(object):
    program_name = os.path.basename(sys.argv[0])

    class __metaclass__(type):
        @property
        def data_extract_id(cls): return b"mb"

    # MultiBit private key backup file (not the wallet file)
    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        try:   data = base64.b64decode(wallet_file.read(20).lstrip()[:12])
        except TypeError: return False
        return data.startswith(b"Salted__")

    def __init__(self, loading = False):
        assert loading, 'use load_from_* to create a ' + self.__class__.__name__
        aes_library_name = CryptoUtil.load_aes256_library().__name__
        self._passwords_per_second = 100000 if aes_library_name == "Crypto" else 5000

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        CryptoUtil.load_aes256_library(warnings=False)
        self.__dict__ = state

    def passwords_per_seconds(self, seconds):
        return max(int(round(self._passwords_per_second * seconds)), 1)

    # Load a Multibit private key backup file (the part of it we need)
    @classmethod
    def load_from_filename(cls, privkey_filename, settings=None):
        with open(privkey_filename) as privkey_file:
            # Multibit privkey files contain base64 text split into multiple lines;
            # we need the first 48 bytes after decoding, which translates to 64 before.
            data = b"".join(privkey_file.read(70).split())  # join multiple lines into one
        if len(data) < 64: raise EOFError("Expected at least 64 bytes of text in the MultiBit private key file")
        data = base64.b64decode(data[:64])
        assert data.startswith(b"Salted__"), "WalletBitcoinCore.load_from_filename: file starts with base64 'Salted__'"
        if len(data) < 48:  raise EOFError("Expected at least 48 bytes of decoded data in the MultiBit private key file")
        self = cls(loading=True)
        self._encrypted_block = data[16:48]  # the first two 16-byte AES blocks
        self._salt            = data[8:16]
        return self

    # Import a MultiBit private key that was extracted by extract-multibit-privkey.py
    @classmethod
    def load_from_data_extract(cls, privkey_data):
        assert len(privkey_data) == 24
        print(cls.program_name + ": WARNING: read the Usage for MultiBit Classic section of Extract_Scripts.md before proceeding", file=sys.stderr)
        self = cls(loading=True)
        self._encrypted_block = privkey_data[8:]  # a single 16-byte AES block
        self._salt            = privkey_data[:8]
        return self

    def difficulty_info(self):
        return "3 MD5 iterations"

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    assert b"1" < b"9" < b"A" < b"Z" < b"a" < b"z"  # the b58 check below assumes ASCII ordering in the interest of speed

    def return_verified_password_or_false(self, orig_passwords):
        # Copy a few globals into local for a small speed boost
        l_md5                 = hashlib.md5
        l_aes256_cbc_decrypt  = CryptoUtil.aes256_cbc_decrypt
        encrypted_block       = self._encrypted_block
        salt                  = self._salt

        # Convert Unicode strings (lazily) to UTF-16 bytestrings, truncating each code unit to 8 bits
        if mode.tstr == unicode:
            passwords = itertools.imap(lambda p: p.encode("utf_16_le", "ignore")[::2], orig_passwords)
        else:
            passwords = orig_passwords

        for count, password in enumerate(passwords, 1):
            salted = password + salt
            key1   = l_md5(salted).digest()
            key2   = l_md5(key1 + salted).digest()
            iv     = l_md5(key2 + salted).digest()
            b58_privkey = l_aes256_cbc_decrypt(key1 + key2, iv, encrypted_block[:16])

            # (all this may be fragile, e.g. what if comments or whitespace precede what's expected in future versions?)
            if b58_privkey[0] in b"LK5Q\x0a#":
                #
                # Does it look like a base58 private key (MultiBit, MultiDoge, or oldest-format Android key backup)?
                if b58_privkey[0] in b"LK5Q":  # private keys always start with L, K, or 5, or for MultiDoge Q
                    for c in b58_privkey[1:]:
                        # If it's outside of the base58 set [1-9A-HJ-NP-Za-km-z], break
                        if c > b"z" or c < b"1" or b"9" < c < b"A" or b"Z" < c < b"a" or c in b"IOl":
                            break
                    # If the loop above doesn't break, it's base58-looking so far
                    else:
                        # If another AES block is available, decrypt and check it as well to avoid false positives
                        if len(encrypted_block) >= 32:
                            b58_privkey = l_aes256_cbc_decrypt(key1 + key2, encrypted_block[:16], encrypted_block[16:32])
                            for c in b58_privkey:
                                if c > b"z" or c < b"1" or b"9" < c < b"A" or b"Z" < c < b"a" or c in b"IOl":
                                    break  # not base58
                            # If the loop above doesn't break, it's base58; we've found it
                            else:
                                return orig_passwords[count-1], count
                        else:
                            # (when no second block is available, there's a 1 in 300 billion false positive rate here)
                            return orig_passwords[count - 1], count
                #
                # Does it look like a bitcoinj protobuf (newest Bitcoin for Android backup)
                elif b58_privkey[2:6] == b"org." and b58_privkey[0] == b"\x0a" and ord(b58_privkey[1]) < 128:
                    for c in b58_privkey[6:14]:
                        # If it doesn't look like a lower alpha domain name of len >= 8 (e.g. 'bitcoin.'), break
                        if c > b"z" or (c < b"a" and c != b"."):
                            break
                    # If the loop above doesn't break, it looks like a domain name; we've found it
                    else:
                        return orig_passwords[count - 1], count
                #
                #  Does it look like a KnC for Android key backup?
                elif b58_privkey == b"# KEEP YOUR PRIV":
                    return orig_passwords[count-1], count

        return False, count
