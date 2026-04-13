#!/usr/bin/env python3


class InvalidKeyLengthError(Exception):
	pass


class InvalidPaddingError(Exception):
	pass


class MissingTagError(Exception):
	pass


class AlreadyEncryptedError(Exception):
	pass


class InvalidOptionsError(Exception):
	pass

