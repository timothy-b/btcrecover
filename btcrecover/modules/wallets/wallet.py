import base64
import struct
import zlib
from btcrecover.modules.utilities.safe_print import error_exit


class Wallet:

    def __init__(self):
        pass

    loaded_wallet = None
    wallet_types = []
    wallet_types_by_id = {}
    # The max wallet file size in bytes (prevents trying to load huge files which clearly aren't wallets)
    MAX_WALLET_FILE_SIZE = 64 * 2**20  # 64 MiB

    @classmethod
    def get_loaded_wallet(cls):
        return cls.loaded_wallet

    @classmethod
    def set_loaded_wallet(cls, wallet):
        cls.loaded_wallet = wallet

    # A class decorator which adds a wallet class to the registered list
    @classmethod
    def register_wallet_class(cls, to_register):
        global wallet_types, wallet_types_by_id
        cls.wallet_types.append(to_register)
        try:
            assert to_register.data_extract_id not in cls.wallet_types_by_id,\
                "register_wallet_class: registered wallet types must have unique data_extract_id's"
            cls.wallet_types_by_id[to_register.data_extract_id] = to_register
        except AttributeError:
            pass
        return to_register

    # Clears the current set of registered wallets (including those registered by default below)
    @classmethod
    def clear_registered_wallets(cls):
        cls.wallet_types = []
        cls.wallet_types_by_id = {}

    # Loads a wallet object and returns it (possibly for external libraries to use)
    @classmethod
    def load_wallet(cls, wallet_filename):
        # Ask each registered wallet type if the file might be of their type,
        # and if so load the wallet
        uncertain_wallet_types = []
        with open(wallet_filename, "rb") as wallet_file:
            for wallet_type in cls.wallet_types:
                found = wallet_type.is_wallet_file(wallet_file)
                if found:
                    wallet_file.close()
                    return wallet_type.load_from_filename(wallet_filename)
                elif found is None:  # None means it might still be this type of wallet...
                    uncertain_wallet_types.append(wallet_type)

        # If the wallet type couldn't be definitively determined, try each
        # questionable type (which must raise ValueError on a load failure)
        uncertain_errors = []
        for wallet_type in uncertain_wallet_types:
            try:
                return wallet_type.load_from_filename(wallet_filename)
            except ValueError as e:
                uncertain_errors.append(wallet_type.__name__ + ": " + unicode(e))

        error_exit("unrecognized wallet format" +
                   ("; heuristic parser(s) reported:\n    " + "\n    ".join(uncertain_errors) if uncertain_errors else ""))

    # Loads a wallet object into the loaded_wallet global from a filename
    @classmethod
    def load_global_wallet(cls, wallet_filename):
        cls.loaded_wallet = Wallet.load_wallet(wallet_filename)

    # Given a base64 string that was produced by one of the extract-* scripts, determines
    # the wallet type and sets the loaded_wallet global to a corresponding wallet object
    @classmethod
    def load_from_base64_key(cls, key_crc_base64):
        try:
            key_crc_data = base64.b64decode(key_crc_base64)
        except TypeError:
            error_exit("encrypted key data is corrupted (invalid base64)")

        # Check the CRC
        if len(key_crc_data) < 8:
            error_exit("encrypted key data is corrupted (too short)")
        key_data = key_crc_data[:-4]
        (key_crc,) = struct.unpack(b"<I", key_crc_data[-4:])
        if zlib.crc32(key_data) & 0xffffffff != key_crc:
            error_exit("encrypted key data is corrupted (failed CRC check)")

        wallet_type = cls.wallet_types_by_id.get(key_data[:2])
        if not wallet_type:
            error_exit("unrecognized encrypted key type '"+key_data[:3]+"'")

        cls.loaded_wallet = wallet_type.load_from_data_extract(key_data[3:])
        return key_crc
