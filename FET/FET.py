#!/usr/bin/env python3
from errors import AlreadyEncryptedError


class SymmetricFET:
	def __init__(self, key, encryptFunc, decryptFunc, algorithm='SymmetricFET', tag=b'\xfa\xe1\n\xcaFC\xb8\xa3\xd3O\xf9KI\r7\xc2a\xec\xdc\xe4\xa1\x99\x99\xa3\xab\x19\xc5\x91\x86\x82\xc0\x9b'):
		self._key = key
		self._tag = tag
		self._algorithm = algorithm
		self.encryptFunc = encryptFunc
		self.decryptFunc = decryptFunc


	def check_tag(self, data):
		if data.startswith(self._tag):
			raise AlreadyEncryptedError(f"This data was already encrypted with {self._algorithm}.")


	def encrypt(self, data):
		self.check_tag(data)
		return self._tag + data


	def decrypt(self, data):
		return data[len(self._tag):]


class AsymmetricFET(SymmetricFET):
	def __init__(self, key, encryptFunc, decryptFunc, sign_func, verify_func, algorithm, tag='\xe4]\xdf\x98T\x11\x83\xfa\xdeR8\x16\xfc#PrR@*\x8c\xc1\x98\x1e)\xb1e\xb1)i\x0b\xb2\xd2'):
		super().__init__(key, encryptFunc, decryptFunc, algorithm, tag)
		self._sign_func = sign_func
		self._verify_func = verify_func


	def sign(self, data):
		return data


	def verify(self, data):
		return data

