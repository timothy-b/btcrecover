import itertools
import os

from btcrecover.btrcpass.wallets.wallet import Wallet
from btcrecover.btrseed.btcrseed import WalletBitcoinj
from btcrecover.btrcpass import mode
from btcrecover.test.test_passwords import pylibscrypt
from btcrecover.utilities.crypto_util import CryptoUtil
from btcrecover.utilities.string_utility import StringUtility


@Wallet.register_wallet_class
class WalletMultiBitHD(WalletBitcoinj):

    class __metaclass__(WalletBitcoinj.__metaclass__):
        @property
        def data_extract_id(cls): return b"m5"
        # id "m2", which *only* supported MultiBit HD prior to v0.5.0 ("m5" supports
        # both before and after), is no longer supported as of btcrecover version 0.15.7

    @staticmethod
    def is_wallet_file(wallet_file): return None  # there's no easy way to check this

    # Load a MultiBit HD wallet file (the part of it we need)
    @classmethod
    def load_from_filename(cls, wallet_filename, settings=None):
        # MultiBit HD wallet files look like completely random bytes, so we
        # require that its name remain unchanged in order to "detect" it
        if os.path.basename(wallet_filename) != "mbhd.wallet.aes":
            raise ValueError("MultiBit HD wallet files must be named mbhd.wallet.aes")

        with open(wallet_filename, "rb") as wallet_file:
            encrypted_data = wallet_file.read(16384)  # typical size is >= 23k
            if len(encrypted_data) < 32:
                raise ValueError("MultiBit HD wallet files must be at least 32 bytes long")

        # The likelihood of of finding a valid encrypted MultiBit HD wallet whose first 16,384
        # bytes have less than 7.8 bits of entropy per byte is... too small for me to figure out
        entropy_bits = StringUtility.est_entropy_bits(encrypted_data)
        if entropy_bits < 7.8:
            raise ValueError("Doesn't look random enough to be an encrypted MultiBit HD wallet (only {:.1f} bits of entropy per byte)".format(entropy_bits))

        self = cls(loading=True)
        self._iv                   = encrypted_data[:16]    # the AES initialization vector (v0.5.0+)
        self._encrypted_block_iv   = encrypted_data[16:32]  # the first 16-byte encrypted block (v0.5.0+)
        self._encrypted_block_noiv = encrypted_data[:16]    # the first 16-byte encrypted block w/hardcoded IV (< v0.5.0)
        return self

    # Import a MultiBit HD encrypted block that was extracted by extract-multibit-hd-data.py
    @classmethod
    def load_from_data_extract(cls, file_data):
        self = cls(loading=True)
        assert len(file_data) == 32
        self._iv                   = file_data[:16]  # the AES initialization vector (v0.5.0+)
        self._encrypted_block_iv   = file_data[16:]  # the first 16-byte encrypted block (v0.5.0+)
        self._encrypted_block_noiv = file_data[:16]  # the first 16-byte encrypted block w/hardcoded IV (< v0.5.0)
        return self

    def difficulty_info(self):
        return "scrypt N, r, p = 16384, 8, 1"

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def return_verified_password_or_false(self, passwords):
        # Copy a few globals into local for a small speed boost
        l_scrypt             = pylibscrypt.scrypt
        l_aes256_cbc_decrypt = CryptoUtil.aes256_cbc_decrypt
        iv                   = self._iv
        encrypted_block_iv   = self._encrypted_block_iv
        encrypted_block_noiv = self._encrypted_block_noiv

        # Convert strings (lazily) to UTF-16BE bytestrings
        passwords = itertools.imap(lambda p: p.encode("utf_16_be", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):
            derived_key = l_scrypt(password, b'\x35\x51\x03\x80\x75\xa3\xb0\xc5', olen=32)  # w/a hardcoded salt
            block_iv    = l_aes256_cbc_decrypt(derived_key, iv, encrypted_block_iv)         # v0.5.0+
            block_noiv  = l_aes256_cbc_decrypt(                                             # < v0.5.0
                derived_key,
                b'\xa3\x44\x39\x1f\x53\x83\x11\xb3\x29\x54\x86\x16\xc4\x89\x72\x3e',        # the hardcoded iv
                encrypted_block_noiv)
            #
            # Does it look like a bitcoinj protobuf file?
            # (there's a 1 in 2 trillion chance this hits but the password is wrong)
            for block in (block_iv, block_noiv):
                if block[2:6] == b"org." and block[0] == b"\x0a" and ord(block[1]) < 128:
                    password = password.decode("utf_16_be", "replace")
                    return password.encode("ascii", "replace") if mode.tstr == str else password, count

        return False, count
