from __future__ import print_function

import hashlib
import os
import sys


class CryptoUtil:
    def __init__(self):
        pass

    @staticmethod
    def _raise(ex):
        raise ex

    missing_pbkdf2_warned = False
    missing_pycrypto_warned = False
    program_name = os.path.basename(sys.argv[0])

    pbkdf2_hmac = staticmethod(lambda hash_name, *args: CryptoUtil._raise(Exception("pbkdf2 library not yet loaded")))
    aes256_cbc_decrypt = staticmethod(lambda key, iv, ciphertext:
                                      CryptoUtil._raise(Exception("aes256 library not yet loaded")))
    aes256_ofb_decrypt = staticmethod(lambda key, iv, ciphertext:
                                      CryptoUtil._raise(Exception("aes256 library not yet loaded")))

    # Creates two decryption functions (in global namespace), aes256_cbc_decrypt() and aes256_ofb_decrypt(),
    # using either PyCrypto if it's available or a pure python library. The created functions each take
    # three bytestring arguments: key, iv, ciphertext. ciphertext must be a multiple of 16 bytes, and any
    # padding present is not stripped.
    @classmethod
    def load_aes256_library(cls, force_purepython=False, warnings=True):
        if not force_purepython:
            try:
                import Crypto.Cipher.AES
                new_aes = Crypto.Cipher.AES.new
                cls.aes256_cbc_decrypt = staticmethod(lambda key, iv, ciphertext:
                    new_aes(key, Crypto.Cipher.AES.MODE_CBC, iv).decrypt(ciphertext))
                cls.aes256_ofb_decrypt = staticmethod(lambda key, iv, ciphertext:
                    new_aes(key, Crypto.Cipher.AES.MODE_OFB, iv).decrypt(ciphertext))
                return Crypto  # just so the caller can check which version was loaded
            except ImportError:
                if warnings and not cls.missing_pycrypto_warned:
                    print(cls.program_name + ": warning: can't find PyCrypto, using aespython instead", file=sys.stderr)
                    cls.missing_pycrypto_warned = True

        # This version is attributed to GitHub user serprex; please see the aespython
        # README.txt for more information. It measures over 30x faster than the more
        # common "slowaes" package (although it's still 30x slower than the PyCrypto)
        #
        import aespython
        expand_key = aespython.key_expander.expandKey
        aes_cipher = aespython.aes_cipher.AESCipher

        def aes256_decrypt_factory(block_mode):
            def aes256_decrypt(key, iv, ciphertext):
                block_cipher = aes_cipher(expand_key(bytearray(key)))
                stream_cipher = block_mode(block_cipher, 16)
                stream_cipher.set_iv(bytearray(iv))
                plaintext = bytearray()
                for i in xrange(0, len(ciphertext), 16):
                    plaintext.extend(stream_cipher.decrypt_block(bytearray(ciphertext[i:i+16])))  # input must be a list
                return str(plaintext)

            return aes256_decrypt

        cls.aes256_cbc_decrypt = staticmethod(aes256_decrypt_factory(aespython.CBCMode))
        cls.aes256_ofb_decrypt = staticmethod(aes256_decrypt_factory(aespython.OFBMode))
        return aespython  # just so the caller can check which version was loaded

    # Creates a key derivation function (in global namespace) named pbkdf2_hmac() using either the
    # hashlib.pbkdf2_hmac from Python 2.7.8+ if it's available, or a pure python library (passlib).
    # The created function takes a hash name, two bytestring arguments and two integer arguments:
    # hash_name (e.g. b"sha1"), password, salt, iter_count, key_len (the length of the returned key)
    @classmethod
    def load_pbkdf2_library(cls, force_purepython=False, warnings=True):
        if not force_purepython:
            try:
                cls.pbkdf2_hmac = hashlib.pbkdf2_hmac
                return hashlib  # just so the caller can check which version was loaded
            except AttributeError:
                if warnings and not cls.missing_pbkdf2_warned:
                    print(cls.program_name +
                          ": warning: hashlib.pbkdf2_hmac requires Python 2.7.8+, using passlib instead",
                          file=sys.stderr)
                    cls.missing_pbkdf2_warned = True

        import passlib.utils.pbkdf2
        cls.passlib_pbkdf2 = staticmethod(passlib.utils.pbkdf2.pbkdf2)
        cls.pbkdf2_hmac = staticmethod(lambda hash_name, *args: cls.passlib_pbkdf2(*args, prf=b"hmac-" + hash_name))
        return passlib  # just so the caller can check which version was loaded
