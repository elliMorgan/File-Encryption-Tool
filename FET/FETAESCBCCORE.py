#!/usr/bin/env python3
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Hash import SHA256
from errors import InvalidPaddingError, InvalidKeyLengthError


class FETAESCBCCORE:
        @staticmethod
        def encrypt(data, key):
                if not (len(key) in [16, 24, 32]):
                        raise InvalidKeyLengthError("AES keys must be 16, 24, or 32 bytes in length (Keylength: %d)."%(len(key)))
                data = pad(data, AES.block_size)
                cipher = AES.new(key, AES.MODE_CBC)
                return cipher.iv + cipher.encrypt(data)


        @staticmethod
        def decrypt(data, key):
                if not (len(key) in [16, 24, 32]):
                        raise InvalidKeyLengthError("AES keys must be 16, 24, or 32 bytes in length (Keylength: %d)."%(len(key)))
                if len(data)%16 != 0:
                        raise InvalidPaddingError("AES-CBC data must be padded to the nearest 16 bytes.")
                iv = data[:16]
                encrypted_data = data[16:]
                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                return unpad(cipher.decrypt(encrypted_data), AES.block_size)


__all__ = ['SHA256', 'PBKDF2', 'get_random_bytes', 'FETAESCBCCORE']

