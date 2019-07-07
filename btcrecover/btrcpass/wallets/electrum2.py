from __future__ import print_function

import base64
import hashlib
import itertools
import os
import sys

from btcrecover.btrcpass.wallets.wallet import Wallet
from btcrecover.btrcpass.wallets.electrum1 import WalletElectrum1
from btcrecover.btrcpass.wallets.electrum_loose_key import WalletElectrumLooseKey
from btcrecover.utilities.crypto_util import CryptoUtil
from btcrecover.btrcpass import mode
from btcrecover.btrcpass.wallets.electrum import WalletElectrum


@Wallet.register_wallet_class
class WalletElectrum2(WalletElectrum):

    class __metaclass__(type):
        @property
        def data_extract_id(cls): return b"e2"

    program_name = os.path.basename(sys.argv[0])

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        # returns "maybe yes" or "definitely no"
        return None if wallet_file.read(1) == b"{" else False

    # Load an Electrum wallet file (the part of it we need)
    @classmethod
    def load_from_filename(cls, wallet_filename, settings=None):
        import json

        with open(wallet_filename) as wallet_file:
            wallet = json.load(wallet_file)
        wallet_type = wallet.get("wallet_type")
        if not wallet_type:
            raise ValueError("Unrecognized wallet format (Electrum2 wallet_type not found)")
        if wallet_type == "old":  # if it's been converted from 1.x to 2.y (y<7), return a WalletElectrum1 object
            return WalletElectrum1._load_from_dict(wallet)
        if not wallet.get("use_encryption"):
            raise ValueError("Electrum2 wallet is not encrypted")
        seed_version = wallet.get("seed_version", "(not found)")
        if wallet.get("seed_version") not in (11, 12, 13) and wallet_type != "imported":  # all 2.x versions as of Oct 2016
            raise NotImplementedError("Unsupported Electrum2 seed version " + unicode(seed_version))

        xprv = None
        while True:  # "loops" exactly once; only here so we've something to break out of

            # Electrum 2.7+ standard wallets have a keystore
            keystore = wallet.get("keystore")
            if keystore:
                keystore_type = keystore.get("type", "(not found)")

                # Wallets originally created by an Electrum 2.x version
                if keystore_type == "bip32":
                    xprv = keystore.get("xprv")
                    if xprv: break

                # Former Electrum 1.x wallet after conversion to Electrum 2.7+ standard-wallet format
                elif keystore_type == "old":
                    seed_data = keystore.get("seed")
                    if seed_data:
                        # Construct and return a WalletElectrum1 object
                        seed_data = base64.b64decode(seed_data)
                        if len(seed_data) != 64:
                            raise RuntimeError("Electrum1 encrypted seed plus iv is not 64 bytes long")
                        self = WalletElectrum1(loading=True)
                        self._iv                  = seed_data[:16]    # only need the 16-byte IV plus
                        self._part_encrypted_data = seed_data[16:32]  # the first 16-byte encrypted block of the seed
                        return self

                # Imported loose private keys
                elif keystore_type == "imported":
                    for privkey in keystore["keypairs"].values():
                        if privkey:
                            # Construct and return a WalletElectrumLooseKey object
                            privkey = base64.b64decode(privkey)
                            if len(privkey) != 80:
                                raise RuntimeError("Electrum2 private key plus iv is not 80 bytes long")
                            self = WalletElectrumLooseKey(loading=True)
                            self._iv                  = privkey[-32:-16]  # only need the 16-byte IV plus
                            self._part_encrypted_data = privkey[-16:]     # the last 16-byte encrypted block of the key
                            return self

                else:
                    print(cls.program_name + ": warning: found unsupported keystore type " + keystore_type, file=sys.stderr)

            # Electrum 2.7+ multisig or 2fa wallet
            for i in itertools.count(1):
                x = wallet.get("x{}/".format(i))
                if not x: break
                x_type = x.get("type", "(not found)")
                if x_type == "bip32":
                    xprv = x.get("xprv")
                    if xprv: break
                else:
                    print(cls.progam_name + ": warning: found unsupported key type " + x_type, file=sys.stderr)
            if xprv: break

            # Electrum 2.0 - 2.6.4 wallet with imported loose private keys
            if wallet_type == "imported":
                for imported in wallet["accounts"]["/x"]["imported"].values():
                    privkey = imported[1] if len(imported) >= 2 else None
                    if privkey:
                        # Construct and return a WalletElectrumLooseKey object
                        privkey = base64.b64decode(privkey)
                        if len(privkey) != 80:
                            raise RuntimeError("Electrum2 private key plus iv is not 80 bytes long")
                        self = WalletElectrumLooseKey(loading=True)
                        self._iv                  = privkey[-32:-16]  # only need the 16-byte IV plus
                        self._part_encrypted_data = privkey[-16:]     # the last 16-byte encrypted block of the key
                        return self

            # Electrum 2.0 - 2.6.4 wallet (of any other wallet type)
            else:
                mpks = wallet.get("master_private_keys")
                if mpks:
                    xprv = mpks.values()[0]
                    break

            raise RuntimeError("No master private keys or seeds found in Electrum2 wallet")

        xprv_data = base64.b64decode(xprv)
        if len(xprv_data) != 128:
            raise RuntimeError("Unexpected Electrum2 encrypted master private key length")
        self = cls(loading=True)
        self._iv                  = xprv_data[:16]    # only need the 16-byte IV plus
        self._part_encrypted_data = xprv_data[16:32]  # the first 16-byte encrypted block of a master privkey
        return self                                   # (the member variable name comes from the base class)

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    assert b"1" < b"9" < b"A" < b"Z" < b"a" < b"z"  # the b58 check below assumes ASCII ordering in the interest of speed
    def return_verified_password_or_false(self, passwords):
        # Copy some vars into local for a small speed boost
        l_sha256             = hashlib.sha256
        l_aes256_cbc_decrypt = CryptoUtil.aes256_cbc_decrypt
        part_encrypted_xprv  = self._part_encrypted_data
        iv                   = self._iv

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        if mode.tstr == unicode:
            passwords = itertools.imap(lambda p: p.encode("utf_8", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):
            key  = l_sha256( l_sha256( password ).digest() ).digest()
            xprv = l_aes256_cbc_decrypt(key, iv, part_encrypted_xprv)

            if xprv.startswith(b"xprv"):  # BIP32 extended private key version bytes
                for c in xprv[4:]:
                    # If it's outside of the base58 set [1-9A-HJ-NP-Za-km-z]
                    if c > b"z" or c < b"1" or b"9" < c < b"A" or b"Z" < c < b"a" or c in b"IOl": break  # not base58
                else:  # if the loop above doesn't break, it's base58
                    return password if mode.tstr == str else password.decode("utf_8", "replace"), count

        return False, count