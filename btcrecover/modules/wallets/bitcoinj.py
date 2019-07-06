from __future__ import print_function

import collections
import itertools
import os
import struct
import sys

from btcrecover.modules.wallets.wallet import Wallet
from btcrecover.modules.utilities.crypto_util import CryptoUtil
from btcrecover.modules import mode

EncryptionParams = collections.namedtuple("EncryptionParams", "salt n r p")


############### bitcoinj ###############

# A namedtuple with the same attributes as the protobuf message object from wallet_pb2
# (it's a global so that it's pickleable)
@Wallet.register_wallet_class
class WalletBitcoinj(object):
    program_name = os.path.basename(sys.argv[0])

    class __metaclass__(type):
        @property
        def data_extract_id(cls): return b"bj"

    def passwords_per_seconds(self, seconds):
        passwords_per_second = self._passwords_per_second
        if hasattr(self, "_scrypt_n"):
            passwords_per_second /= self._scrypt_n / 16384  # scaled by default N
            passwords_per_second /= self._scrypt_r / 8      # scaled by default r
            passwords_per_second /= self._scrypt_p / 1      # scaled by default p
        return max(int(round(passwords_per_second * seconds)), 1)

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        if wallet_file.read(1) == b"\x0a":  # protobuf field number 1 of type length-delimited
            network_identifier_len = ord(wallet_file.read(1))
            if 1 <= network_identifier_len < 128:
                wallet_file.seek(2 + network_identifier_len)
                c = wallet_file.read(1)
                if c and c in b"\x12\x1a":   # field number 2 or 3 of type length-delimited
                    return True
        return False

    def __init__(self, loading = False):
        assert loading, 'use load_from_* to create a ' + self.__class__.__name__
        global pylibscrypt
        import pylibscrypt
        # This is the base estimate for the scrypt N,r,p defaults of 16384,8,1
        if not pylibscrypt._done:
            print(self.program_name + ": warning: can't find an scrypt library, performance will be severely degraded", file=sys.stderr)
            self._passwords_per_second = 0.03
        else:
            self._passwords_per_second = 14
        CryptoUtil.load_aes256_library()

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        global pylibscrypt
        CryptoUtil.load_aes256_library(warnings=False)
        self.__dict__ = state

    # Load a bitcoinj wallet file (the part of it we need)
    @classmethod
    def load_from_filename(cls, wallet_filename):
        with open(wallet_filename, "rb") as wallet_file:
            filedata = wallet_file.read(Wallet.MAX_WALLET_FILE_SIZE)  # up to 64M, typical size is a few k
        return cls._load_from_filedata(filedata)

    @classmethod
    def _load_from_filedata(cls, filedata):

        import btcrecover.wallet_pb2 as wallet_pb2
        pb_wallet = wallet_pb2.Wallet()
        pb_wallet.ParseFromString(filedata)
        if pb_wallet.encryption_type == wallet_pb2.Wallet.UNENCRYPTED:
            raise ValueError("bitcoinj wallet is not encrypted")
        if pb_wallet.encryption_type != wallet_pb2.Wallet.ENCRYPTED_SCRYPT_AES:
            raise NotImplementedError("Unsupported bitcoinj encryption type "+unicode(pb_wallet.encryption_type))
        if not pb_wallet.HasField("encryption_parameters"):
            raise ValueError("bitcoinj wallet is missing its scrypt encryption parameters")

        for key in pb_wallet.key:
            if  key.type in (wallet_pb2.Key.ENCRYPTED_SCRYPT_AES, wallet_pb2.Key.DETERMINISTIC_KEY) and key.HasField("encrypted_data"):
                encrypted_len = len(key.encrypted_data.encrypted_private_key)
                if encrypted_len == 48:
                    # only need the final 2 encrypted blocks (half of it padding) plus the scrypt parameters
                    self = cls(loading=True)
                    self._part_encrypted_key = key.encrypted_data.encrypted_private_key[-32:]
                    self._scrypt_salt = pb_wallet.encryption_parameters.salt
                    self._scrypt_n    = pb_wallet.encryption_parameters.n
                    self._scrypt_r    = pb_wallet.encryption_parameters.r
                    self._scrypt_p    = pb_wallet.encryption_parameters.p
                    return self
                print(cls.program_name +": warning: ignoring encrypted key of unexpected length ("+unicode(encrypted_len)+")", file=sys.stderr)

        raise ValueError("No encrypted keys found in bitcoinj wallet")

    # Import a bitcoinj private key that was extracted by extract-bitcoinj-privkey.py
    @classmethod
    def load_from_data_extract(cls, privkey_data):
        self = cls(loading=True)
        # The final 2 encrypted blocks
        self._part_encrypted_key = privkey_data[:32]
        # The scrypt parameters
        self._scrypt_salt = privkey_data[32:40]
        (self._scrypt_n, self._scrypt_r, self._scrypt_p) = struct.unpack(b"< I H H", privkey_data[40:])
        return self

    def difficulty_info(self):
        return "scrypt N, r, p = {}, {}, {}".format(self._scrypt_n, self._scrypt_r, self._scrypt_p)

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def return_verified_password_or_false(self, passwords):
        # Copy a few globals into local for a small speed boost
        l_scrypt             = pylibscrypt.scrypt
        l_aes256_cbc_decrypt = CryptoUtil.aes256_cbc_decrypt
        part_encrypted_key   = self._part_encrypted_key
        scrypt_salt          = self._scrypt_salt
        scrypt_n             = self._scrypt_n
        scrypt_r             = self._scrypt_r
        scrypt_p             = self._scrypt_p

        # Convert strings (lazily) to UTF-16BE bytestrings
        passwords = itertools.imap(lambda p: p.encode("utf_16_be", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):
            derived_key = l_scrypt(password, scrypt_salt, scrypt_n, scrypt_r, scrypt_p, 32)
            part_key    = l_aes256_cbc_decrypt(derived_key, part_encrypted_key[:16], part_encrypted_key[16:])
            #
            # If the last block (bytes 16-31) of part_encrypted_key is all padding, we've found it
            if part_key == b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10":
                password = password.decode("utf_16_be", "replace")
                return password.encode("ascii", "replace") if mode.tstr == str else password, count

        return False, count