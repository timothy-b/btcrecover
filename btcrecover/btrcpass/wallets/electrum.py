from btcrecover.utilities.crypto_util import CryptoUtil


# Common base class for all Electrum wallets
class WalletElectrum(object):
    def __init__(self, loading = False):
        assert loading, 'use load_from_* to create a ' + self.__class__.__name__
        aes_library_name = CryptoUtil.load_aes256_library().__name__
        self._passwords_per_second = 100000 if aes_library_name == "Crypto" else 5000

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        CryptoUtil.load_aes256_library(warnings=False)
        self.__dict__ = state

    def passwords_per_seconds(self, seconds):
        return max(int(round(self._passwords_per_second * seconds)), 1)

    # Import Electrum encrypted data extracted by an extract-electrum* script
    @classmethod
    def load_from_data_extract(cls, data):
        assert len(data) == 32
        self = cls(loading=True)
        self._iv = data[:16]  # the 16-byte IV
        self._part_encrypted_data = data[16:]  # 16-bytes of encrypted data
        return self

    @staticmethod
    def difficulty_info():
        return "2 SHA-256 iterations"
