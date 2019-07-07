import base64
import hashlib
import itertools

from btcrecover.btrcpass.wallets.wallet import Wallet
from btcrecover.btrcpass.wallets.electrum import WalletElectrum
from btcrecover.utilities.crypto_util import CryptoUtil
from btcrecover.btrcpass import mode


@Wallet.register_wallet_class
class WalletElectrum1(WalletElectrum):

    class __metaclass__(type):
        @property
        def data_extract_id(cls): return b"el"

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        # returns "maybe yes" or "definitely no"
        return None if wallet_file.read(2) == b"{'" else False

    # Load an Electrum wallet file (the part of it we need)
    @classmethod
    def load_from_filename(cls, wallet_filename, settings=None):
        from ast import literal_eval
        with open(wallet_filename) as wallet_file:
            try:
                wallet = literal_eval(wallet_file.read(Wallet.MAX_WALLET_FILE_SIZE))  # up to 64M, typical size is a few k
            except SyntaxError as e:  # translate any SyntaxError into a
                raise ValueError(e)   # ValueError as expected by load_wallet()
        return cls._load_from_dict(wallet)

    @classmethod
    def _load_from_dict(cls, wallet):
        seed_version = wallet.get("seed_version")
        if seed_version is None:             raise ValueError("Unrecognized wallet format (Electrum1 seed_version not found)")
        if seed_version != 4:                raise NotImplementedError("Unsupported Electrum1 seed version " + unicode(seed_version))
        if not wallet.get("use_encryption"): raise RuntimeError("Electrum1 wallet is not encrypted")
        seed_data = base64.b64decode(wallet["seed"])
        if len(seed_data) != 64:             raise RuntimeError("Electrum1 encrypted seed plus iv is not 64 bytes long")
        self = cls(loading=True)
        self._iv                  = seed_data[:16]    # only need the 16-byte IV plus
        self._part_encrypted_data = seed_data[16:32]  # the first 16-byte encrypted block of the seed
        return self

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    assert b"0" < b"9" < b"a" < b"f"  # the hex check below assumes ASCII ordering in the interest of speed
    def return_verified_password_or_false(self, passwords):
        # Copy some vars into local for a small speed boost
        l_sha256             = hashlib.sha256
        l_aes256_cbc_decrypt = CryptoUtil.aes256_cbc_decrypt
        part_encrypted_seed  = self._part_encrypted_data
        iv                   = self._iv

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        if mode.tstr == unicode:
            passwords = itertools.imap(lambda p: p.encode("utf_8", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):
            key  = l_sha256( l_sha256( password ).digest() ).digest()
            seed = l_aes256_cbc_decrypt(key, iv, part_encrypted_seed)
            # If the first 16 bytes of the encrypted seed is all lower-case hex, we've found it
            for c in seed:
                if c > b"f" or c < b"0" or b"9" < c < b"a": break  # not hex
            else:  # if the loop above doesn't break, it's all hex
                return password if mode.tstr == str else password.decode("utf_8", "replace"), count

        return False, count
