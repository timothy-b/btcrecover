import base64
import hashlib
import itertools

from btcrecover.btcrseed import WalletBitcoinj
from btcrecover.modules import mode
from btcrecover.modules.utilities.safe_print import error_exit
from btcrecover.modules.wallets.wallet import Wallet
from btcrecover.modules.utilities.crypto_util import CryptoUtil


@Wallet.register_wallet_class
class WalletBither(object):

    class __metaclass__(type):
        @property
        def data_extract_id(cls): return b"bt"

    def passwords_per_seconds(self, seconds):
        return max(int(round(self._passwords_per_second * seconds)), 1)

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        # returns "maybe yes" or "definitely no" (mSIGNA wallets are also SQLite 3)
        return None if wallet_file.read(16) == b"SQLite format 3\0" else False

    def __init__(self, loading = False):
        assert loading, 'use load_from_* to create a ' + self.__class__.__name__
        # loading crypto libraries is done in load_from_*

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        global pylibscrypt, coincurve
        CryptoUtil.load_aes256_library(warnings=False)
        self.__dict__ = state

    # Load a Bither wallet file (the part of it we need)
    @classmethod
    def load_from_filename(cls, wallet_filename):
        import sqlite3
        wallet_conn = sqlite3.connect(wallet_filename)

        is_bitcoinj_compatible  = None
        # Try to find an encrypted loose key first; they're faster to check
        try:
            wallet_cur = wallet_conn.execute(b"SELECT encrypt_private_key FROM addresses LIMIT 1")
            key_data   = wallet_cur.fetchone()
            if key_data:
                key_data = key_data[0]
                is_bitcoinj_compatible = True  # if found, the KDF & encryption are bitcoinj compatible
            else:
                e1 = "no encrypted keys present in addresses table"
        except sqlite3.OperationalError as e1:
            if str(e1).startswith(b"no such table"):
                key_data = None
            else: raise  # unexpected error

        if not key_data:
            # Newer wallets w/o loose keys have a password_seed table with a single row
            try:
                wallet_cur = wallet_conn.execute(b"SELECT password_seed FROM password_seed LIMIT 1")
                key_data   = wallet_cur.fetchone()
            except sqlite3.OperationalError as e2:
                raise ValueError("Not a Bither wallet: {}, {}".format(e1, e2))  # it might be an mSIGNA wallet
            if not key_data:
                error_exit("can't find an encrypted key or password seed in the Bither wallet")
            key_data = key_data[0]

        # Create a bitcoinj wallet (which loads required libraries); we may or may not actually use it
        bitcoinj_wallet = WalletBitcoinj(loading=True)

        # key_data is forward-slash delimited; it contains an optional pubkey hash, an encrypted key, an IV, a salt
        key_data = key_data.split(b"/")
        if len(key_data) == 1:
            key_data = key_data.split(b":")  # old Bither wallets used ":" as the delimiter
        pubkey_hash = key_data.pop(0) if len(key_data) == 4 else None
        if len(key_data) != 3:
            error_exit("unrecognized Bither encrypted key format (expected 3-4 slash-delimited elements, found {})"
                       .format(len(key_data)))
        (encrypted_key, iv, salt) = key_data
        encrypted_key = base64.b16decode(encrypted_key, casefold=True)

        # The first salt byte is optionally a flags byte
        salt = base64.b16decode(salt, casefold=True)
        if len(salt) == 9:
            flags = ord(salt[0])
            salt  = salt[1:]
        else:
            flags = 1  # this is the is_compressed flag; if not present it defaults to compressed
            if len(salt) != 8:
                error_exit("unexpected salt length ({}) in Bither wallet".format(len(salt)))

        # Return a WalletBitcoinj object to do the work if it's compatible with one (it's faster)
        if is_bitcoinj_compatible:
            if len(encrypted_key) != 48:
                error_exit("unexpected encrypted key length in Bither wallet (expected 48, found {})"
                           .format(len(encrypted_key)))
            # only need the last 2 encrypted blocks (half of which is padding) plus the salt (don't need the iv)
            bitcoinj_wallet._part_encrypted_key = encrypted_key[-32:]
            bitcoinj_wallet._scrypt_salt = salt
            bitcoinj_wallet._scrypt_n    = 16384  # Bither hardcodes the rest
            bitcoinj_wallet._scrypt_r    = 8
            bitcoinj_wallet._scrypt_p    = 1
            return bitcoinj_wallet

        # Constuct and return a WalletBither object
        else:
            if not pubkey_hash:
                error_exit("pubkey hash160 not present in Bither password_seed")
            global coincurve
            import coincurve
            self = cls(loading=True)
            self._passwords_per_second = bitcoinj_wallet._passwords_per_second  # they're the same
            self._iv_encrypted_key     = base64.b16decode(iv, casefold=True) + encrypted_key
            self._salt                 = salt  # already hex decoded
            self._pubkey_hash160       = base64.b16decode(pubkey_hash, casefold=True)[1:]  # strip the bitcoin version byte
            self._is_compressed        = bool(flags & 1)  # 1 is the is_compressed flag
            return self

    # Import a Bither private key that was extracted by extract-bither-privkey.py
    @classmethod
    def load_from_data_extract(cls, privkey_data):
        assert len(privkey_data) == 40, "extract-bither-privkey.py only extracts keys from bitcoinj compatible wallets"
        bitcoinj_wallet = WalletBitcoinj(loading=True)
        # The final 2 encrypted blocks
        bitcoinj_wallet._part_encrypted_key = privkey_data[:32]
        # The 8-byte salt and hardcoded scrypt parameters
        bitcoinj_wallet._scrypt_salt = privkey_data[32:]
        bitcoinj_wallet._scrypt_n    = 16384
        bitcoinj_wallet._scrypt_r    = 8
        bitcoinj_wallet._scrypt_p    = 1
        return bitcoinj_wallet

    def difficulty_info(self):
        return "scrypt N, r, p = 16384, 8, 1 + ECC"

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def return_verified_password_or_false(self, passwords):
        # Copy a few globals into local for a small speed boost
        l_scrypt             = pylibscrypt.scrypt
        l_aes256_cbc_decrypt = CryptoUtil.aes256_cbc_decrypt
        l_sha256             = hashlib.sha256
        hashlib_new          = hashlib.new
        iv_encrypted_key     = self._iv_encrypted_key  # 16-byte iv + encrypted_key
        salt                 = self._salt
        pubkey_from_secret   = coincurve.PublicKey.from_valid_secret
        cutils               = coincurve.utils

        # Convert strings (lazily) to UTF-16BE bytestrings
        passwords = itertools.imap(lambda p: p.encode("utf_16_be", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):
            derived_aeskey = l_scrypt(password, salt, 16384, 8, 1, 32)  # scrypt params are hardcoded except the salt

            # Decrypt and check if the last 16-byte block of iv_encrypted_key is valid PKCS7 padding
            privkey_end = l_aes256_cbc_decrypt(derived_aeskey, iv_encrypted_key[-32:-16], iv_encrypted_key[-16:])
            padding_len = ord(privkey_end[-1])
            if not (1 <= padding_len <= 16 and privkey_end.endswith(chr(padding_len) * padding_len)):
                continue
            privkey_end = privkey_end[:-padding_len]  # trim the padding

            # Decrypt the rest of the encrypted_key, derive its pubkey, and compare it to what's expected
            privkey = l_aes256_cbc_decrypt(derived_aeskey, iv_encrypted_key[:16], iv_encrypted_key[16:-16]) + privkey_end
            # privkey can be any size, but libsecp256k1 expects a 256-bit key < the group's order:
            privkey = cutils.int_to_bytes_padded( cutils.bytes_to_int(privkey) % cutils.GROUP_ORDER_INT )
            pubkey  = pubkey_from_secret(privkey).format(self._is_compressed)
            # Compute the hash160 of the public key, and check for a match
            if hashlib_new("ripemd160", l_sha256(pubkey).digest()).digest() == self._pubkey_hash160:
                password = password.decode("utf_16_be", "replace")
                return password.encode("ascii", "replace") if mode.tstr == str else password, count

        return False, count
