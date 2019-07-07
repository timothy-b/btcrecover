import base64
import hashlib
import itertools
import json
import re
import struct

from btcrecover.btrcpass.wallets.wallet import Wallet
from btcrecover.btrcpass import mode
from btcrecover.utilities.crypto_util import CryptoUtil
from btcrecover.btrcpass.wallets.blockchain import WalletBlockchain
from btcrecover.utilities.prompt import prompt_unicode_password
from btcrecover.utilities.safe_print import error_exit


@Wallet.register_wallet_class
class WalletBlockchainSecondpass(WalletBlockchain):

    class __metaclass__(WalletBlockchain.__metaclass__):
        @property
        def data_extract_id(cls):    return b"bs"

    @staticmethod
    def is_wallet_file(wallet_file): return False  # never auto-detected as this wallet type

    # Load a Blockchain wallet file to get the "Second Password" hash,
    # decrypting the wallet if necessary
    @classmethod
    def load_from_filename(cls, wallet_filename, password=None, force_purepython=False, setting=None):
        from uuid import UUID

        with open(wallet_filename) as wallet_file:
            data = wallet_file.read(Wallet.MAX_WALLET_FILE_SIZE)  # up to 64M, typical size is a few k

        try:
            # Assuming the wallet is encrypted, get the encrypted data
            data, iter_count = cls._parse_encrypted_blockchain_wallet(data)
        except ValueError as e:
            # This is the one error to expect and ignore which occurs when the wallet isn't encrypted
            if e.args[0] == "Can't find either version nor payload attributes in Blockchain file":
                pass
            else:
                raise
        except StandardError as e:
            error_exit(unicode(e))
        else:
            # If there were no problems getting the encrypted data, decrypt it
            if not password:
                password = prompt_unicode_password(
                    b"Please enter the Blockchain wallet's main password: ",
                    "encrypted Blockchain files must be decrypted before searching for the second password")
            password = password.encode("utf_8")
            data, salt_and_iv = data[16:], data[:16]
            CryptoUtil.load_pbkdf2_library(force_purepython)
            CryptoUtil.load_aes256_library(force_purepython)
            #
            # These are a bit fragile in the interest of simplicity because they assume the guid is the first
            # name in the JSON object, although this has always been the case as of 6/2014 (since 12/2011)
            #
            # Encryption scheme used in newer wallets
            def decrypt_current(iter_count):
                key = CryptoUtil.pbkdf2_hmac(b"sha1", password, salt_and_iv, iter_count, 32)
                decrypted = CryptoUtil.aes256_cbc_decrypt(key, salt_and_iv, data)    # CBC mode
                padding   = ord(decrypted[-1:])                           # ISO 10126 padding length
                return decrypted[:-padding] if 1 <= padding <= 16 and re.match(b'{\s*"guid"', decrypted) else None
            #
            # Encryption scheme only used in version 0.0 wallets (N.B. this is untested)
            def decrypt_old():
                key = CryptoUtil.pbkdf2_hmac(b"sha1", password, salt_and_iv, 1, 32)  # only 1 iteration
                decrypted  = CryptoUtil.aes256_ofb_decrypt(key, salt_and_iv, data)   # OFB mode
                # The 16-byte last block, reversed, with all but the first byte of ISO 7816-4 padding removed:
                last_block = tuple(itertools.dropwhile(lambda x: x==b"\0", decrypted[:15:-1]))
                padding    = 17 - len(last_block)                         # ISO 7816-4 padding length
                return decrypted[:-padding] if 1 <= padding <= 16 and decrypted[-padding] == b"\x80" and re.match(b'{\s*"guid"', decrypted) else None
            #
            if iter_count:  # v2.0 wallets have a single possible encryption scheme
                data = decrypt_current(iter_count)
            else:           # v0.0 wallets have three different possible encryption schemes
                data = decrypt_current(10) or decrypt_current(1) or decrypt_old()
            if not data:
                error_exit("can't decrypt wallet (wrong main password?)")

        # Load and parse the now-decrypted wallet
        data = json.loads(data)
        if not data.get("double_encryption"):
            error_exit("double encryption with a second password is not enabled for this wallet")

        # Extract and save what we need to perform checking on the second password
        try:
            iter_count = data["options"]["pbkdf2_iterations"]
            if not isinstance(iter_count, int) or iter_count < 1:
                raise ValueError("Invalid Blockchain second password pbkdf2_iterations " + unicode(iter_count))
        except KeyError:
            iter_count = 0
        self = cls(iter_count, loading=True)
        #
        self._password_hash = base64.b16decode(data["dpasswordhash"], casefold=True)
        if len(self._password_hash) != 32:
            raise ValueError("Blockchain second password hash is not 32 bytes long")
        #
        self._salt = data["sharedKey"].encode("ascii")
        if str(UUID(self._salt)) != self._salt:
            raise ValueError("Unrecognized Blockchain salt format")

        return self

    # Import extracted Blockchain file data necessary for second password checking
    @classmethod
    def load_from_data_extract(cls, file_data):
        from uuid import UUID
        # These are the same second password hash, salt, iteration count retrieved above
        password_hash, uuid_salt, iter_count = struct.unpack(b"< 32s 16s I", file_data)
        self = cls(iter_count, loading=True)
        self._salt          = str(UUID(bytes=uuid_salt))
        self._password_hash = password_hash
        return self

    def difficulty_info(self):
        return ("{:,}".format(self._iter_count) if self._iter_count else "1-10") + " SHA-256 iterations"

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def return_verified_password_or_false(self, passwords):
        # Copy vars into locals for a small speed boost
        l_sha256 = hashlib.sha256
        password_hash = self._password_hash
        salt          = self._salt
        iter_count    = self._iter_count

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        if mode.tstr == unicode:
            passwords = itertools.imap(lambda p: p.encode("utf_8", "ignore"), passwords)

        # Newer wallets specify an iter_count and use something similar to PBKDF1 with SHA-256
        if iter_count:
            for count, password in enumerate(passwords, 1):
                running_hash = salt + password
                for i in xrange(iter_count):
                    running_hash = l_sha256(running_hash).digest()
                if running_hash == password_hash:
                    return password if mode.tstr == str else password.decode("utf_8", "replace"), count

        # Older wallets used one of three password hashing schemes
        else:
            for count, password in enumerate(passwords, 1):
                running_hash = l_sha256(salt + password).digest()
                # Just a single SHA-256 hash
                if running_hash == password_hash:
                    return password if mode.tstr == str else password.decode("utf_8", "replace"), count
                # Exactly 10 hashes (the first of which was done above)
                for i in xrange(9):
                    running_hash = l_sha256(running_hash).digest()
                if running_hash == password_hash:
                    return password if mode.tstr == str else password.decode("utf_8", "replace"), count
                # A single unsalted hash
                if l_sha256(password).digest() == password_hash:
                    return password if mode.tstr == str else password.decode("utf_8", "replace"), count

        return False, count
