import base64
import json
import struct

from btcrecover.modules import mode
from btcrecover.modules.utilities.string_utility import StringUtility
from btcrecover.modules.utilities.crypto_util import CryptoUtil
from btcrecover.modules.wallets.wallet import Wallet


@Wallet.register_wallet_class
class WalletBlockchain(object):

    class __metaclass__(type):
        @property
        def data_extract_id(cls):    return b"bk"

    @staticmethod
    def is_wallet_file(wallet_file): return None  # there's no easy way to check this

    def __init__(self, iter_count, loading = False):
        assert loading, 'use load_from_* to create a ' + self.__class__.__name__
        pbkdf2_library_name = CryptoUtil.load_pbkdf2_library().__name__
        aes_library_name    = CryptoUtil.load_aes256_library().__name__
        self._iter_count           = iter_count
        self._passwords_per_second = 400000 if pbkdf2_library_name == "hashlib" else 100000
        if iter_count == 0:  # if it's a v0 wallet
            iter_count = 10
        self._passwords_per_second /= iter_count
        if aes_library_name != "Crypto" and self._passwords_per_second > 2000:
            self._passwords_per_second = 2000

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        CryptoUtil.load_pbkdf2_library(warnings=False)
        CryptoUtil.load_aes256_library(warnings=False)
        self.__dict__ = state

    def passwords_per_seconds(self, seconds):
        return max(int(round(self._passwords_per_second * seconds)), 1)

    # Load a Blockchain wallet file (the part of it we need)
    @classmethod
    def load_from_filename(cls, wallet_filename):
        with open(wallet_filename) as wallet_file:
            data, iter_count = cls._parse_encrypted_blockchain_wallet(wallet_file.read(Wallet.MAX_WALLET_FILE_SIZE))  # up to 64M, typical size is a few k
        self = cls(iter_count, loading=True)
        self._salt_and_iv     = data[:16]    # only need the salt_and_iv plus
        self._encrypted_block = data[16:32]  # the first 16-byte encrypted block
        return self

    # Parse the contents of an encrypted blockchain wallet (v0 - v3) or config file returning two
    # values in a tuple: (encrypted_data_blob, iter_count) where iter_count == 0 for v0 wallets
    @staticmethod
    def _parse_encrypted_blockchain_wallet(data):
        iter_count = 0

        while True:  # "loops" exactly once; only here so we've something to break out of
            # Most blockchain files (except v0.0 wallets) are JSON encoded; try to parse it as such
            try:
                data = json.loads(data)
            except ValueError: break

            # Config files have no version attribute; they encapsulate the wallet file plus some detrius
            if "version" not in data:
                try:
                    data = data["payload"]  # extract the wallet file from the config
                except KeyError:
                    raise ValueError("Can't find either version nor payload attributes in Blockchain file")
                try:
                    data = json.loads(data)  # try again to parse a v2.0/v3.0 JSON-encoded wallet file
                except ValueError: break

            # Extract what's needed from a v2.0/3.0 wallet file
            if data["version"] > 3:
                raise NotImplementedError("Unsupported Blockchain wallet version " + unicode(data["version"]))
            iter_count = data["pbkdf2_iterations"]
            if not isinstance(iter_count, int) or iter_count < 1:
                raise ValueError("Invalid Blockchain pbkdf2_iterations " + unicode(iter_count))
            data = data["payload"]

            break

        # Either the encrypted data was extracted from the "payload" field above, or
        # this is a v0.0 wallet file whose entire contents consist of the encrypted data
        try:
            data = base64.b64decode(data)
        except TypeError as e:
            raise ValueError("Can't base64-decode Blockchain wallet: "+unicode(e))
        if len(data) < 32:
            raise ValueError("Encrypted Blockchain data is too short")
        if len(data) % 16 != 0:
            raise ValueError("Encrypted Blockchain data length is not divisible by the encryption blocksize (16)")

        # If this is (possibly) a v0.0 (a.k.a. v1) wallet file, check that the encrypted data
        # looks random, otherwise this could be some other type of base64-encoded file such
        # as a MultiBit key file (it should be safe to skip this test for v2.0+ wallets)
        if not iter_count:  # if this is a v0.0 wallet
            # The likelihood of of finding a valid encrypted blockchain wallet (even at its minimum length
            # of about 500 bytes) with less than 7.4 bits of entropy per byte is less than 1 in 10^6
            # (decreased test below to 7.2 after being shown a wallet with just under 7.4 entropy bits)
            entropy_bits = StringUtility.est_entropy_bits(data)
            if entropy_bits < 7.2:
                raise ValueError("Doesn't look random enough to be an encrypted Blockchain wallet (only {:.1f} bits of entropy per byte)".format(entropy_bits))

        return data, iter_count  # iter_count == 0 for v0 wallets

    # Import extracted Blockchain file data necessary for main password checking
    @classmethod
    def load_from_data_extract(cls, file_data):
        # These are the same first encrypted block, salt_and_iv, iteration count retrieved above
        encrypted_block, salt_and_iv, iter_count = struct.unpack(b"< 16s 16s I", file_data)
        self = cls(iter_count, loading=True)
        self._encrypted_block = encrypted_block
        self._salt_and_iv     = salt_and_iv
        return self

    def difficulty_info(self):
        return "{:,} PBKDF2-SHA1 iterations".format(self._iter_count or 10)

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def return_verified_password_or_false(self, passwords):
        # Copy a few globals into local for a small speed boost
        l_pbkdf2_hmac        = CryptoUtil.pbkdf2_hmac
        l_aes256_cbc_decrypt = CryptoUtil.aes256_cbc_decrypt
        l_aes256_ofb_decrypt = CryptoUtil.aes256_ofb_decrypt
        encrypted_block      = self._encrypted_block
        salt_and_iv          = self._salt_and_iv
        iter_count           = self._iter_count

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        if mode.tstr == unicode:
            passwords = map(lambda p: p.encode("utf_8", "ignore"), passwords)

        v0 = not iter_count     # version 0.0 wallets don't specify an iter_count
        if v0: iter_count = 10  # the default iter_count for version 0.0 wallets
        for count, password in enumerate(passwords, 1):
            key = l_pbkdf2_hmac(b"sha1", password, salt_and_iv, iter_count, 32)          # iter_count iterations
            unencrypted_block = l_aes256_cbc_decrypt(key, salt_and_iv, encrypted_block)  # CBC mode
            # A bit fragile because it assumes the guid is in the first encrypted block,
            # although this has always been the case as of 6/2014 (since 12/2011)
            if unencrypted_block[0] == b"{" and b'"guid"' in unencrypted_block:
                return password if mode.tstr == str else password.decode("utf_8", "replace"), count

        if v0:
            # Try the older encryption schemes possibly used in v0.0 wallets
            for count, password in enumerate(passwords, 1):
                key = l_pbkdf2_hmac(b"sha1", password, salt_and_iv, 1, 32)                   # only 1 iteration
                unencrypted_block = l_aes256_cbc_decrypt(key, salt_and_iv, encrypted_block)  # CBC mode
                if unencrypted_block[0] == b"{" and b'"guid"' in unencrypted_block:
                    return password if mode.tstr == str else password.decode("utf_8", "replace"), count
                unencrypted_block = l_aes256_ofb_decrypt(key, salt_and_iv, encrypted_block)  # OFB mode
                if unencrypted_block[0] == b"{" and b'"guid"' in unencrypted_block:
                    return password if mode.tstr == str else password.decode("utf_8", "replace"), count

        return False, count
