#!/usr/bin/env python3
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome import Signature
from Cryptodome.Signature import PKCS1_v1_5, PKCS1_PSS
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256
from errors import InvalidKeyLengthError
from FETAESCBCCORE import FETAESCBCCORE


import os


class FETRSACORE:
	@staticmethod
	def encrypt(data, key, aes_key_len=32):
		rsa_cipher = PKCS1_OAEP.new(key)
		aes_key = get_random_bytes(aes_key_len)
		encrypted_aes_key = rsa_cipher.encrypt(aes_key)
		return encrypted_aes_key + FETAESCBCCORE.encrypt(data, aes_key)


	@staticmethod
	def decrypt(data, key):
		rsa_cipher = PKCS1_OAEP.new(key)
		key_len = key.size_in_bytes()
		encrypted_aes_key = data[:key_len]
		aes_key = rsa_cipher.decrypt(encrypted_aes_key)
		return FETAESCBCCORE.decrypt(data[key_len:], aes_key)


	@staticmethod
	def generate_key(bits, *args, **kwargs):
		if bits < 1024:
			raise InvalidKeyLengthError(f"RSA keys must be greater than 1024 bits.")
		return RSA.generate(bits, *args, **kwargs)


	@staticmethod
	def sign(message, key, sig='PKCS1_v1_5', hash_module=SHA256):
		hash_object = hash_module.new(message)
		# print(dir(Signature))
		sig_scheme = getattr(Signature, sig).new(key)
		return sig_scheme.sign(hash_object)


	@staticmethod
	def verify(message, signature, key, sig='PKCS1_v1_5', hash_module=SHA256):
		hash_object = hash_module.new(message)
		verify = getattr(Signature, sig).new(key)
		verify.verify(hash_object, signature)


	@staticmethod
	def export_key_to_file(file, key, *args, **kwargs):
		exported_key = key.export_key(*args, **kwargs)
		with open(file, 'wb') as handle:
			handle.write(exported_key)


	@staticmethod
	def import_key_from_file(file, *args, **kwargs):
		with open(file, 'rb') as handle:
			keydata = handle.read()
		return RSA.import_key(keydata, *args, **kwargs)

