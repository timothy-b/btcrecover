import hashlib
import itertools

from btcrecover import btcrseed, CryptoUtil
from btcrecover.modules import mode
from btcrecover.modules.utilities.safe_print import error_exit


# @register_wallet_class - not a "registered" wallet since there are no wallet files nor extracts
class WalletBIP39(object):

    def __init__(self, mpk=None, addresses=None, address_limit=None, addressdb_filename=None,
                 mnemonic=None, lang=None, path=None, wallet_type="bitcoin", is_performance=False):

        if wallet_type == "bitcoin":
            btcrseed_cls = btcrseed.WalletBIP39
        elif wallet_type == "ethereum":
            if addressdb_filename:
                error_exit("can't use an address database with Ethereum wallets")
            btcrseed_cls = btcrseed.WalletEthereum
        else:
            error_exit("--wallet-type must be one of: bitcoin, ethereum")

        global normalize, hmac
        from unicodedata import normalize
        import hmac
        CryptoUtil.load_pbkdf2_library()

        # Create a btcrseed.WalletBIP39 object which will do most of the work;
        # this also interactively prompts the user if not enough command-line options were included
        if addressdb_filename:
            print("Loading address database ...")
            from btcrecover.addressset import AddressSet
            hash160s = AddressSet.fromfile(open(addressdb_filename, "rb"))
        else:
            hash160s = None
        self.btcrseed_wallet = btcrseed_cls.create_from_params(
            mpk, addresses, address_limit, hash160s, path, is_performance)
        if is_performance and not mnemonic:
            mnemonic = "certain come keen collect slab gauge photo inside mechanic deny leader drop"
        self.btcrseed_wallet.config_mnemonic(mnemonic, lang)

        # Verify that the entered mnemonic is valid
        if not self.btcrseed_wallet.verify_mnemonic_syntax(btcrseed.mnemonic_ids_guess):
            error_exit("one or more words are missing from the mnemonic")
        if not self.btcrseed_wallet._verify_checksum(btcrseed.mnemonic_ids_guess):
            error_exit("invalid mnemonic (the checksum is wrong)")
        # We just verified the mnemonic checksum is valid, so 100% of the guesses will also be valid:
        self.btcrseed_wallet._checksum_ratio = 1

        self._mnemonic = b" ".join(btcrseed.mnemonic_ids_guess)

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        global normalize, hmac
        from unicodedata import normalize
        import hmac
        CryptoUtil.load_pbkdf2_library(warnings=False)
        self.__dict__ = state

    def passwords_per_seconds(self, seconds):
        return self.btcrseed_wallet.passwords_per_seconds(seconds)

    @staticmethod
    def difficulty_info():
        return "2048 PBKDF2-SHA512 iterations + ECC"

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def return_verified_password_or_false(self, passwords):
        # Convert Unicode strings (lazily) to normalized UTF-8 bytestrings
        if mode.tstr == unicode:
            passwords = itertools.imap(lambda p: normalize("NFKD", p).encode("utf_8", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):
            seed_bytes = CryptoUtil.pbkdf2_hmac(b"sha512", self._mnemonic, b"mnemonic" + password, 2048)
            seed_bytes = hmac.new(b"Bitcoin seed", seed_bytes, hashlib.sha512).digest()
            if self.btcrseed_wallet._verify_seed(seed_bytes):
                return password if mode.tstr == str else password.decode("utf_8", "replace"), count

        return False, count
