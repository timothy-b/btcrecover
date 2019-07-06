import base64
import json

from btcrecover.modules.wallets.wallet import Wallet
from btcrecover.modules.wallets.bitcoin_core import WalletBitcoinCore


@Wallet.register_wallet_class
class WalletPywallet(WalletBitcoinCore):

    class __metaclass__(WalletBitcoinCore.__metaclass__):
        @property
        def data_extract_id(cls):    return False  # there is none

    @staticmethod
    def is_wallet_file(wallet_file): return None   # there's no easy way to check this

    # Load a Bitcoin Core encrypted master key from a file created by pywallet.py --dumpwallet
    @classmethod
    def load_from_filename(cls, wallet_filename):
        # pywallet dump files are largish json files often preceded by a bunch of error messages;
        # search through the file in 16k blocks looking for a particular string which occurs twice
        # inside the mkey object we need (because it appears twice, we're guaranteed one copy
        # will appear whole in at least one block even if the other is split across blocks).
        #
        # For the first block, give up if this doesn't look like a text file
        with open(wallet_filename) as wallet_file:
            last_block = b""
            cur_block  = wallet_file.read(16384)
            if sum(1 for c in cur_block if ord(c) > 126 or ord(c) == 0) > 512:  # about 3%
                raise ValueError("Unrecognized pywallet format (does not look like ASCII text)")
            while cur_block:
                found_at = cur_block.find(b'"nDerivation')
                if found_at >= 0:
                    break
                last_block = cur_block
                cur_block = wallet_file.read(16384)
            else:
                raise ValueError("Unrecognized pywallet format (can't find mkey)")

            cur_block = last_block + cur_block + wallet_file.read(4096)
        found_at = cur_block.rfind(b"{", 0, found_at + len(last_block))
        if found_at < 0:
            raise ValueError("Unrecognized pywallet format (can't find mkey opening brace)")
        wallet = json.JSONDecoder().raw_decode(cur_block[found_at:])[0]

        if not all(name in wallet for name in ("nDerivationIterations", "nDerivationMethod", "nID", "salt")):
            raise ValueError("Unrecognized pywallet format (can't find all mkey attributes)")

        if wallet["nID"] != 1:
            raise NotImplementedError("Unsupported Bitcoin Core wallet ID " + wallet["nID"])
        if wallet["nDerivationMethod"] != 0:
            raise NotImplementedError("Unsupported Bitcoin Core key derivation method " + wallet["nDerivationMethod"])

        if "encrypted_key" in wallet:
            encrypted_master_key = wallet["encrypted_key"]
        elif "crypted_key" in wallet:
            encrypted_master_key = wallet["crypted_key"]
        else:
            raise ValueError("Unrecognized pywallet format (can't find [en]crypted_key attribute)")

        # These are the same as retrieved and saved by load_bitcoincore_wallet()
        self = cls(loading=True)
        encrypted_master_key = base64.b16decode(encrypted_master_key, casefold=True)
        self._salt = base64.b16decode(wallet["salt"], True)
        self._iter_count = int(wallet["nDerivationIterations"])

        if len(encrypted_master_key) != 48:
            raise NotImplementedError("Unsupported encrypted master key length")
        if len(self._salt) != 8:
            raise NotImplementedError("Unsupported salt length")
        if self._iter_count <= 0:
            raise NotImplementedError("Unsupported iteration count")

        # only need the final 2 encrypted blocks (half of it padding) plus the salt and iter_count saved above
        self._part_encrypted_master_key = encrypted_master_key[-32:]
        return self
