import base64
import hashlib
import itertools
import math

from btcrecover.modules.wallets.wallet import Wallet
from btcrecover.modules.utilities.crypto_util import CryptoUtil
from btcrecover.modules import mode
from btcrecover.modules.wallets.electrum import WalletElectrum


@Wallet.register_wallet_class
class WalletElectrumLooseKey(WalletElectrum):

    class __metaclass__(type):
        @property
        def data_extract_id(cls):    return b"ek"

    @staticmethod
    def is_wallet_file(wallet_file): return False  # WalletElectrum2.load_from_filename() creates us

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    assert b"1" < b"9" < b"A" < b"Z" < b"a" < b"z"  # the b58 check below assumes ASCII ordering in the interest of speed
    def return_verified_password_or_false(self, passwords):
        # Copy some vars into local for a small speed boost
        l_sha256              = hashlib.sha256
        l_aes256_cbc_decrypt  = CryptoUtil.aes256_cbc_decrypt
        encrypted_privkey_end = self._part_encrypted_data
        iv                    = self._iv

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        if mode.tstr == unicode:
            passwords = itertools.imap(lambda p: p.encode("utf_8", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):
            key         = l_sha256( l_sha256( password ).digest() ).digest()
            privkey_end = l_aes256_cbc_decrypt(key, iv, encrypted_privkey_end)
            padding_len = ord(privkey_end[-1])
            # Check for valid PKCS7 padding for a 52 or 51 byte "WIF" private key
            # (4*16-byte-blocks == 64, 64 - 52 or 51 == 12 or 13
            if (padding_len == 12 or padding_len == 13) and privkey_end.endswith(chr(padding_len) * padding_len):
                for c in privkey_end[:-padding_len]:
                    # If it's outside of the base58 set [1-9A-HJ-NP-Za-km-z]
                    if c > b"z" or c < b"1" or b"9" < c < b"A" or b"Z" < c < b"a" or c in b"IOl": break  # not base58
                else:  # if the loop above doesn't break, it's base58
                    return password if mode.tstr == str else password.decode("utf_8", "replace"), count

        return False, count


@Wallet.register_wallet_class
class WalletElectrum28(object):
    coincurve = None

    def passwords_per_seconds(self, seconds):
        return max(int(round(self._passwords_per_second * seconds)), 1)

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        try:   data = base64.b64decode(wallet_file.read(8))
        except TypeError: return False
        return data[:4] == b"BIE1"  # Electrum 2.8+ magic

    def __init__(self, loading=False):
        assert loading, 'use load_from_* to create a ' + self.__class__.__name__
        import coincurve, hmac
        self.__class__.hmac = hmac
        self.__class__.coincurve = coincurve
        pbkdf2_library_name = CryptoUtil.load_pbkdf2_library().__name__
        self._aes_library_name = CryptoUtil.load_aes256_library().__name__
        self._passwords_per_second = 800 if pbkdf2_library_name == "hashlib" else 140

    def __getstate__(self):
        # Serialize unpicklable coincurve.PublicKey object
        state = self.__dict__.copy()
        state["_ephemeral_pubkey"] = self._ephemeral_pubkey.format(compressed=False)
        return state

    def __setstate__(self, state):
        # Restore coincurve.PublicKey object and (re-)load the required libraries
        import hmac, coincurve
        self.__class__.hmac = hmac
        self.__class__.coincurve = coincurve
        CryptoUtil.load_pbkdf2_library(warnings=False)
        CryptoUtil.load_aes256_library(warnings=False)
        self.__dict__ = state
        self._ephemeral_pubkey = coincurve.PublicKey(self._ephemeral_pubkey)

    # Load an Electrum 2.8 encrypted wallet file
    @classmethod
    def load_from_filename(cls, wallet_filename):
        with open(wallet_filename) as wallet_file:
            data = wallet_file.read(Wallet.MAX_WALLET_FILE_SIZE)  # up to 64M, typical size is a few k
        if len(data) >= Wallet.MAX_WALLET_FILE_SIZE:
            raise ValueError("Encrypted Electrum wallet file is too big")
        MIN_LEN = 37 + 32 + 32  # header + ciphertext + trailer
        if len(data) < MIN_LEN * 4 / 3:
            raise EOFError("Expected at least {} bytes of text in the Electrum wallet file".format(int(math.ceil(MIN_LEN * 4 / 3))))
        data = base64.b64decode(data)
        if len(data) < MIN_LEN:
            raise EOFError("Expected at least {} bytes of decoded data in the Electrum wallet file".format(MIN_LEN))
        assert data[:4] == b"BIE1", "wallet file has Electrum 2.8+ magic"

        self = cls(loading=True)
        self._ephemeral_pubkey = cls.coincurve.PublicKey(data[4:37])
        self._ciphertext_beg = data[37:37+16]  # first ciphertext block
        self._ciphertext_end = data[-64:-32]   # last two blocks (before mac)
        self._mac = data[-32:]
        self._all_but_mac = data[:-32]
        return self

    def difficulty_info(self):
        return "1024 PBKDF2-SHA512 iterations + ECC"

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def return_verified_password_or_false(self, passwords):
        cutils = self.coincurve.utils

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        if mode.tstr == unicode:
            passwords = itertools.imap(lambda p: p.encode("utf_8", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):

            # Derive the ECIES shared public key, and from it, the AES and HMAC keys
            static_privkey = CryptoUtil.pbkdf2_hmac(b"sha512", password, b"", 1024, 64)
            # Electrum uses a 512-bit private key (why?), but libsecp256k1 expects a 256-bit key < group's order:
            static_privkey = cutils.int_to_bytes(cutils.bytes_to_int(static_privkey) % cutils.GROUP_ORDER_INT )
            shared_pubkey = self._ephemeral_pubkey.multiply(static_privkey).format()
            keys = hashlib.sha512(shared_pubkey).digest()

            # Only run these initial checks if we have a fast AES library
            if self._aes_library_name != 'aespython':
                # Check for the expected zlib and deflate headers in the first 16-byte decrypted block
                plaintext_block = CryptoUtil.aes256_cbc_decrypt(keys[16:32], keys[:16], self._ciphertext_beg)  # key, iv, ciphertext
                if not (plaintext_block.startswith(b"\x78\x9c") and ord(plaintext_block[2]) & 0x7 == 0x5):
                    continue

                # Check for valid PKCS7 padding in the last 16-byte decrypted block
                plaintext_block = CryptoUtil.aes256_cbc_decrypt(keys[16:32], self._ciphertext_end[:16], self._ciphertext_end[16:])  # key, iv, ciphertext
                padding_len = ord(plaintext_block[-1])
                if not (1 <= padding_len <= 16 and plaintext_block.endswith(chr(padding_len) * padding_len)):
                    continue

            # Check the MAC
            computed_mac = self.hmac.new(keys[32:], self._all_but_mac, hashlib.sha256).digest()
            if computed_mac == self._mac:
                return password if mode.tstr == str else password.decode("utf_8", "replace"), count

        return False, count
