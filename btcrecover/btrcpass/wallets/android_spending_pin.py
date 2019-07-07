import base64
import hashlib

from btcrecover.btrcpass.wallets.bitcoinj import WalletBitcoinj
from btcrecover.utilities.crypto_util import CryptoUtil
from btcrecover.utilities.prompt import prompt_unicode_password
from btcrecover.utilities.safe_print import error_exit

# don't @register_wallet_class -- it's never auto-detected and never used for a --data-extract
class WalletAndroidSpendingPIN(WalletBitcoinj):

    # Decrypt a Bitcoin Wallet for Android/BlackBerry backup into a standard bitcoinj wallet, and load it
    @classmethod
    def load_from_filename(cls, wallet_filename, password=None, force_purepython=False, settings=None):
        with open(wallet_filename, "rb") as wallet_file:
            # If we're given an unencrypted backup, just return a WalletBitcoinj
            if WalletBitcoinj.is_wallet_file(wallet_file):
                wallet_file.close()
                return WalletBitcoinj.load_from_filename(wallet_filename)

            wallet_file.seek(0)
            data = wallet_file.read(Wallet.MAX_WALLET_FILE_SIZE)  # up to 64M, typical size is a few k

        data = data.replace(b"\r", b"").replace(b"\n", b"")
        data = base64.b64decode(data)
        if not data.startswith(b"Salted__"):
            raise ValueError("Not a Bitcoin Wallet for Android/BlackBerry encrypted backup (missing 'Salted__')")
        if len(data) < 32:
            raise EOFError  ("Expected at least 32 bytes of decoded data in the encrypted backup file")
        if len(data) % 16 != 0:
            raise ValueError("Not a valid Bitcoin Wallet for Android/BlackBerry encrypted backup (size not divisible by 16)")
        salt = data[8:16]
        data = data[16:]

        if not password:
            password = prompt_unicode_password(
                b"Please enter the password for the Bitcoin Wallet for Android/BlackBerry backup: ",
                "encrypted Bitcoin Wallet for Android/BlackBerry backups must be decrypted before searching for the PIN")
        # Convert Unicode string to a UTF-16 bytestring, truncating each code unit to 8 bits
        password = password.encode("utf_16_le", "ignore")[::2]

        # Decrypt the backup file (OpenSSL style)
        CryptoUtil.load_aes256_library(force_purepython)
        salted = password + salt
        key1   = hashlib.md5(salted).digest()
        key2   = hashlib.md5(key1 + salted).digest()
        iv     = hashlib.md5(key2 + salted).digest()
        data   = CryptoUtil.aes256_cbc_decrypt(key1 + key2, iv, data)
        from cStringIO import StringIO
        if not WalletBitcoinj.is_wallet_file(StringIO(data[:100])):
            error_exit("can't decrypt wallet (wrong password?)")
        # Validate and remove the PKCS7 padding
        padding_len = ord(data[-1])
        if not (1 <= padding_len <= 16 and data.endswith(chr(padding_len) * padding_len)):
            error_exit("can't decrypt wallet, invalid padding (wrong password?)")

        return cls._load_from_filedata(data[:-padding_len])  # WalletBitcoinj._load_from_filedata() parses the bitcoinj wallet
