#!/usr/bin/env python3
import os
import sys
import logging
import datetime
import atexit
import threading
import getpass


fet_module_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
sys.path.append(fet_module_dir)
fet_module_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../FET"))
sys.path.append(fet_module_dir)


import click
from FET import InvalidKeyLengthError, InvalidOptionsError, InvalidPaddingError, MissingTagError, AlreadyEncryptedError, InvalidKeyLengthError, FET, LogVerbosityCheck, StatusBar, SHA256, get_random_bytes, PBKDF2, FETAESCBCCORE, FETRSACORE, Status


class FETRSA(FET.AsymmetricFET):
	def __init__(self, key, encryptFunc=FETRSACORE.encrypt, decryptFunc=FETRSACORE.decrypt, sign_func=FETRSACORE.sign, verify_func=FETRSACORE.verify, tag=b'\x8e\xf6\xc8)\x9a\x14\xd1,\xf3\xe8\xdc\x8d+\x8e\x98/\x8f\xd2,\xc4\x93A\xa3\xda\x12ra6\xa4\x1e\x02\xce'):
		super().__init__(key, encryptFunc, decryptFunc, sign_func, verify_func, 'RSA', tag)


	def encrypt(self, data):
		super().check_tag(data)		
		return super().encrypt(self.encryptFunc(data, self._key))


	def decrypt(self, data):
		return self.decryptFunc(super().decrypt(data), self._key)


	def sign(self, message):
		return super().sign(self._sign_func(message, self._key))


	def verify(self, message, signature):
		return super().verify(self._verify_func(message, signature, self._key))		


	@staticmethod
	def export_key_to_file(*args, **kwargs):
		try:
			FETRSACORE.export_key_to_file(*args, **kwargs)
		except PermissionError:
			log_check.warn_with_date_and_time_if_v(f"Error generating keys: Error opening {file}: The program did not have the required permissions.")
			Status.status_bad(f'Error opening {file}: invalid permissions.')
		except OSError as e:
			log_check.warn_with_date_and_time_if_v(f"Error generating keys: Error opening {file}: An OSError was raised({e}).")
			Status.status_bad(f'Error opening {file}: OSError raised ({e}).')
		except FileNotFoundError as e:
			log_check.warn_with_date_and_time_if_v(f"Error generating keys: Error opening {file}: The file did not exist.")
			Status.status_bad(f'Error opening {file}: File does not exist.')
		except Exception as e:
			log_check.warn_with_date_and_time_if_v(f"Error generating keys: Error opening {file}: Unknown.")
			Status.status_bad(f'Error opening {file}: Unknown error ({e}).')


	@staticmethod
	def generate_key(keylength, file, pubkey_file, key_format, encrypt):
		log_check.log_with_date_and_time_if_v(f"Generating %s {keylength} bit RSA key in {key_format} format."%('an encrypted' if encrypt else 'a'))
		try:
			key = FETRSACORE.generate_key(keylength)
			if encrypt:
				passkey = get_passkey(True)
			else:
				passkey = None
			FETRSA.export_key_to_file(file=file, key=key, format=key_format, passphrase=passkey, protection='PBKDF2WithHMAC-SHA512AndAES256-CBC' if encrypt else None, pkcs=8 if encrypt else 1)
			FETRSA.export_key_to_file(file=pubkey_file, key=key.public_key(), format=key_format)
			log_check.log_with_date_and_time_if_v(f"Generated %s {keylength} bit RSA key in {key_format} format."%('an encrypted' if encrypt else 'a'))
		except InvalidKeyLengthError:
			log_check.warn_with_date_and_time_if_v(f"Error generating keys: the keylength({keylength}) was invalid")
			Status.status_bad('The keylength must be larger than 1024 bits.')


	@staticmethod
	def test(sb, times, keylength):
		log_check.log_with_date_and_time_if_v(f"Running {times} encryption and decryption tests on RSA({keylength} bit).")
		for i in range(times):
			log_check.log_with_date_and_time_if_v(f"Running test {i+1}/{times}.")
			log_check.log_with_date_and_time_if_v(f"Generating key.")
			fetRSA = FETRSA(FETRSACORE.generate_key(keylength))
			data = get_random_bytes(32)
			log_check.log_with_date_and_time_if_v(f"data: {data}")
			encrypted = fetRSA.encrypt(data);
			decrypted = fetRSA.decrypt(encrypted)
			log_check.log_with_date_and_time_if_v(f"encrypted: {encrypted}")
			log_check.log_with_date_and_time_if_v(f"decrypted: {decrypted}")
			if data == decrypted:
				log_check.log_with_date_and_time_if_v(f"Check {i+1}/{times} passed.")
				sb.update(1, f'Check {i+1}/{times} passed.')
			else:
				log_check.warn_with_date_and_and_time_if_v(f"Check {i+1}/{times} failed.")
				sb.fail(f'Check {i+1}/{times} failed')
				return
		log_check.log_with_date_and_time_if_v(f"All checks passed.")



def encryptFilesTh(fetRSA, files, sb):
	i = 0
	totalFiles = len(files)
	while len(files) > 0:
		i+=1
		file = files.pop(0)
		try:
			with open(file, 'rb') as handle:
				data = handle.read()
			encrypted_data = fetRSA.encrypt(data)
			with open(file, 'wb') as handle:
				handle.write(encrypted_data)
			sb.update(1, f'Encrypted {file}')
			log_check.log_with_date_and_time_if_v(f"Successfully encrypted {os.path.abspath(file)}")
		except InvalidKeyLengthError as e:
			log_check.warn_with_date_and_time_if_v(f"Error encrypting {file}: The keylength was invalid.")
			sb.fail(f'{file}: The keylength is invalid.', True)
		except AlreadyEncryptedError as e:
			log_check.warn_with_date_and_time_if_v(f"Error encrypting {file}: The file has already been encrypted.")
			sb.fail(f'{file}: This file has already been encrypted.', False, False)
		except PermissionError as e:
			log_check.warn_with_date_and_time_if_v(f"Error encrypting {file}: The program did not have the required permissions.")
			sb.fail(f'{file}: Invalid permissions.', False, False)
		except OSError as e:
			log_check.warn_with_date_and_time_if_v(f"Error encrypting {file}: An OSError was raised({e}).")
			sb.fail(f'{file}: OSError raised ({e}).', False, False)
		except FileNotFoundError as e:
			log_check.warn_with_date_and_time_if_v(f"Error encrypting {file}: The file did not exist.")
			sb.fail(f'{file}: File does not exist.', False, False)
		except Exception as e:
			log_check.warn_with_date_and_time_if_v(f"Error encrypting {file}: Unknown.")
			sb.fail(f'{file}: Unknown error ({e}).', True, True)




def decryptFilesTh(fetRSA, files, sb):
	i = 0
	totalFiles = len(files)
	while len(files) > 0:
		i+=1
		file = files.pop(0)
		try:
			with open(file, 'rb') as handle:
				data = handle.read()
			encrypted_data = fetRSA.decrypt(data)
			with open(file, 'wb') as handle:
				handle.write(encrypted_data)
			log_check.log_with_date_and_time_if_v(f"Successfully decrypted {os.path.abspath(file)}")
			sb.update(1, f'Decrypted {file}')
		except InvalidKeyLengthError as e:
			log_check.warn_with_date_and_time_if_v(f"The keylength was invalid.")
			sb.fail(f'{file}: The keylength is invalid.', True)
		except MissingTagError as e:
			log_check.warn_with_date_and_time_if_v(f"The file was not encrypted.")
			sb.fail(f'{file}: This file has not been encrypted.', False, False)
		except ValueError as e:
			log_check.warn_with_date_and_time_if_v(f"The data couldn't unpad, indicating the password was wrong.")
			sb.fail(f'{file}: The key is wrong.', True, False)
		except PermissionError as e:
			log_check.warn_with_date_and_time_if_v(f"The program did not have the required permissions.")
			sb.fail(f'{file}: Invalid permissions.', False, False)
		except OSError as e:
			log_check.warn_with_date_and_time_if_v(f"An OSError was raised({e}).")
			sb.fail(f'{file}: OSError raised ({e}).', False, False)
		except FileNotFoundError as e:
			log_check.warn_with_date_and_time_if_v(f"The file did not exist.")
			sb.fail(f'{file}: File does not exist.', False, False)
		except Exception as e:
			log_check.warn_with_date_and_time_if_v(f"Unknown.")
			sb.fail(f'{file}: Unknown error ({e}).', True, True)


def signMessage(key, file, sigfile, status):
	try:
		with open(file, 'rb') as handle:
			message = handle.read()
		Status.status_good('Signing message.')
		log_check.log_with_date_and_time_if_v(f"Signing message.")
		fetRSA = FETRSA(key)
		signature = fetRSA.sign(message)
		log_check.log_with_date_and_time_if_v(f"Signed message.")
		Status.status_good('Signed message.')
		log_check.log_with_date_and_time_if_v(f"writing signature to {sigfile}.")
		Status.status_message(f"writing signature to {sigfile}.")
		with open(sigfile, 'wb') as handle:
			handle.write(signature)
		log_check.log_with_date_and_time_if_v(f"Wrote signature to {sigfile}.")
		Status.status_good(f"Wrote signature to {sigfile}.")
		return signature
	except InvalidKeyLengthError as e:
		log_check.warn_with_date_and_time_if_v(f"The keylength was invalid.")
		Status.status_bad(f"The keylength was invalid.")
	except MissingTagError as e:
		log_check.warn_with_date_and_time_if_v(f"The file was not encrypted.")
		Status.status_bad(f"The file was not encrypted.")
	except ValueError as e:
		log_check.warn_with_date_and_time_if_v(f"The data couldn't unpad, indicating the password was wrong.")
		Status.status_bad(f"The data couldn't unpad, indicating the password was wrong.")
	except PermissionError as e:
		log_check.warn_with_date_and_time_if_v(f"The program did not have the required permissions.")
		Status.status_bad(f"The program did not have the required permissions.")
	except OSError as e:
		log_check.warn_with_date_and_time_if_v(f"An OSError was raised({e}).")
		Status.status_bad(f"An OSError was raised({e}).")
	except FileNotFoundError as e:
		log_check.warn_with_date_and_time_if_v(f"The file did not exist.")
		Status.status_bad(f"The file did not exist.")
	except Exception as e:
		log_check.warn_with_date_and_time_if_v(f"Unknown: {e}.")
		Status.status_bad(f"Unknown: {e}.")


def verifySignature(key, file, sigfile, status):
	log_check.log_with_date_and_time_if_v(f"Verifying signature.")
	fetRSA = FETRSA(key)
	try:
		Status.status_message(f'Reading message.')
		with open(file, 'rb') as handle:
			message = handle.read()
		Status.status_good(f'Reading signature.')
		with open(sigfile, 'rb') as handle:
			signature = handle.read()
		Status.status_message(f'Verifying message')
		fetRSA.verify(message, signature)
		Status.status_good(f'Verified signature.')
		log_check.log_with_date_and_time_if_v(f"Verified signature.")
		return True
	except InvalidKeyLengthError as e:
		log_check.warn_with_date_and_time_if_v(f"The keylength was invalid.")
		Status.status_bad(f"The keylength was invalid.")
	except MissingTagError as e:
		log_check.warn_with_date_and_time_if_v(f"The file was not encrypted.")
		Status.status_bad(f"The file was not encrypted.")
	except ValueError as e:
		log_check.warn_with_date_and_time_if_v(f"The data couldn't unpad, indicating the password was wrong.")
		Status.status_bad(f"The data couldn't unpad, indicating the password was wrong.")
	except PermissionError as e:
		log_check.warn_with_date_and_time_if_v(f"The program did not have the required permissions.")
		Status.status_bad(f"The program did not have the required permissions.")
	except OSError as e:
		log_check.warn_with_date_and_time_if_v(f"An OSError was raised({e}).")
		Status.status_bad(f"An OSError was raised({e}).")
	except FileNotFoundError as e:
		log_check.warn_with_date_and_time_if_v(f"The file did not exist.")
		Status.status_bad(f"The file did not exist.")
	except Exception as e:
		log_check.warn_with_date_and_time_if_v(f"Unknown: {e}.")
		Status.status_bad(f"Unknown: {e}.")
	Status.status_bad(f"Could not verify signature.")
	log_check.log_with_date_and_time_if_v(f"Could not verify signature.")
	return False


def walkDirs(files):
	for f in files:
		if os.path.isdir(f):
			for root, folder, walkFiles in os.walk(f):
				for walkFile in walkFiles:
					files.append(os.path.join(root, walkFile))
			files.remove(f)


def encryptFiles(key, files, sb, nThreads):
	threads = []
	walkDirs(files)
	# key = FETRSACORE.import_key_from_file(keyfile)
	log_check.log_with_date_and_time_if_v(f"Encrypting %d files with %d threads, and a %d keylength."%(len(files), nThreads, key.size_in_bytes()))
	fetRSA = FETRSA(key)
	for i in range(nThreads):
		t = threading.Thread(target=encryptFilesTh, args=(fetRSA, files, sb))
		threads.append(t)
	for i in range(nThreads):
		log_check.log_with_date_and_time_if_v(f"Started thread {i+1}/{nThreads}")
		threads[i].start()
	for i in range(nThreads):
		log_check.log_with_date_and_time_if_v(f"Joining thread {i+1}/{nThreads}")
		threads[i].join()


def decryptFiles(key, files, sb, nThreads):
	threads = []
	walkDirs(files)
	log_check.log_with_date_and_time_if_v(f"Encrypting %d files with %d threads, and a %d keylength."%(len(files), nThreads, key.size_in_bytes()))
	fetRSA = FETRSA(key)
	for i in range(nThreads):
		t = threading.Thread(target=decryptFilesTh, args=(fetRSA, files, sb))
		threads.append(t)
	for i in range(nThreads):
		log_check.log_with_date_and_time_if_v(f"Started thread {i+1}/{nThreads}")
		threads[i].start()
	for i in range(nThreads):
		log_check.log_with_date_and_time_if_v(f"Joining thread {i+1}/{nThreads}")
		threads[i].join()


def get_passkey(verify, prompt="Password: "):
	passkey = getpass.getpass(prompt=prompt)
	if verify:
		test = getpass.getpass("Please enter password again: ")
		if test == passkey:
			return passkey
		else:
			Status.status_bad('The passwords don\'t match.')
			sys.exit(1)


def import_encrypted_key_from_file(keyfile):
	while True:
		try:
			passkey = getpass.getpass()
			key = FETRSACORE.import_key_from_file(keyfile, passkey)
			return key
		except KeyboardInterrupt:
			sys.exit(0)
		except:
			Status.status_bad('Incorrect. Please try again.')


@click.group()
def commands():
	pass


@click.command(help='Encrypt a file or directory.')
@click.argument('files', type=click.Path(exists=True), nargs=-1, required=True)
@click.option('-kf', '--keyfile', type=click.Path(exists=True), required=True, help='The file to obtain the key from.')
@click.option('-nt', '--n-threads', help='The number of threads(creating more threads typically make issues with the status bar).', type=click.INT, default=1)
@click.option('-l', '--log', is_flag=True, help="Enable logging.", default=False)
@click.option('-lf', '--log-file', help='The file to output logs to. Required if logging is enabled.', required=False)
def encrypt(files, keyfile, n_threads, log, log_file):
	try:
		log_check.init_log_verbosity_check(log, log_file)
	except InvalidOptionsError:
		print('Please use the -lf option to specify the log file.')
		return
	try:
		key = FETRSACORE.import_key_from_file(keyfile)
	except ValueError:
		key = import_encrypted_key_from_file(keyfile)
	sb = StatusBar('Encrypting files(%d total)...'%(len(files)), len(files))
	encryptFiles(key, list(files), sb, n_threads)


@click.command(help='Decrypt a file or directory.')
@click.argument('files', type=click.Path(exists=True), nargs=-1, required=True)
@click.option('-kf', '--keyfile', type=click.Path(exists=True), required=True, help='The file to obtain the key from.')
@click.option('-nt', '--n-threads', help='The number of threads(creating more threads typically make issues with the status bar).', type=click.INT, default=1)
@click.option('-l', '--log', is_flag=True, help="Enable logging.", default=False)
@click.option('-lf', '--log-file', help='The file to output logs to. Required if logging is enabled.', required=False)
def decrypt(files, keyfile, n_threads, log, log_file):
	try:
		log_check.init_log_verbosity_check(log, log_file)
	except InvalidOptionsError:
		print('Please use the -lf option to specify the log file.')
		return
	try:
		key = FETRSACORE.import_key_from_file(keyfile)
	except ValueError:
		key = import_encrypted_key_from_file(keyfile)
	if not key.has_private():
		print('Decryption requires a private key')
		return
	sb = StatusBar('Decrypting files(%d total)...'%(len(files)), len(files))
	decryptFiles(key, list(files), sb, n_threads)


@click.command(help='Sign a message.')
@click.option('-f', '--file', help='The file with the message.', required=True)
@click.option('-sf', '--sigfile', help='The file to write the signature to.', required=True)
@click.option('-kf', '--keyfile', type=click.Path(exists=True), required=True, help='The file to obtain the key from.')
@click.option('-l', '--log', is_flag=True, help="Enable logging.", default=False)
@click.option('-lf', '--log-file', help='The file to output logs to. Required if logging is enabled.', required=False)
def sign(file, sigfile, keyfile, log, log_file):
	try:
		log_check.init_log_verbosity_check(log, log_file)
	except InvalidOptionsError:
		print('Please use the -lf option to specify the log file.')
		return
	try:
		key = FETRSACORE.import_key_from_file(keyfile)
	except ValueError:
		key = import_encrypted_key_from_file(keyfile)
	signMessage(key, file, sigfile, Status)


@click.command(help='Verify a message.')
@click.option('-f', '--file', help='The file with the message.', required=True)
@click.option('-sf', '--sigfile', help='The file with the signature.', required=True)
@click.option('-kf', '--keyfile', type=click.Path(exists=True), required=True, help='The file to obtain the key from.')
@click.option('-l', '--log', is_flag=True, help="Enable logging.", default=False)
@click.option('-lf', '--log-file', help='The file to output logs to. Required if logging is enabled.', required=False)
def verify(file, sigfile, keyfile, log, log_file):
	try:
		log_check.init_log_verbosity_check(log, log_file)
	except InvalidOptionsError:
		print('Please use the -lf option to specify the log file.')
		return
	try:
		key = FETRSACORE.import_key_from_file(keyfile)
	except ValueError:
		key = import_encrypted_key_from_file(keyfile)
	verifySignature(key, file, sigfile, Status)


@click.command(help='Generate RSA private/public key pairs.')
@click.argument('KEYLENGTH', type=click.INT, default=2048)
@click.option('-f', '--file', help='The file to write the private key to.', default='rsa.pem')
@click.option('-pkf', '--public-key-file', help='The file to write public the key to.', default=None)
@click.option('-kf', '--key-format', type=click.Choice(['PEM', 'DER']), default='PEM', help='RSA key format.')
@click.option('-e', '--encrypt', is_flag=True, default=False, help='Whether or not to encrypt the RSA key with AES.')
@click.option('-l', '--log', is_flag=True, help="Enable logging.", default=False)
@click.option('-lf', '--log-file', help='The file to output logs to. Required if logging is enabled.', required=False)
def generate(keylength, file, public_key_file, key_format, encrypt, log, log_file):
	try:
		log_check.init_log_verbosity_check(log, log_file)
	except InvalidOptionsError:
		print('Please use the -lf option to specify the log file.')
		return
	if public_key_file == None:
		public_key_file = f"{file}.pub"
	FETRSA.generate_key(keylength, file, public_key_file, key_format, encrypt)


@click.command(help='Change the password of an encrypted RSA private key, or encrypt an unencrypted RSA private key.')
@click.argument('FILE')
@click.option('-kf', '--key-format', type=click.Choice(['PEM', 'DER']), default='PEM', help='RSA key format.')
def change_password(file, key_format):
	try:
		key = FETRSACORE.import_key_from_file(file)
	except ValueError:
		key = import_encrypted_key_from_file(file)
	new_password = get_passkey(True, 'Enter the new password: ')
	FETRSA.export_key_to_file(file=file, key=key, format=key_format, passphrase=new_password, protection='PBKDF2WithHMAC-SHA512AndAES256-CBC', pkcs=8)


@click.command(help='Ensure RSA is functioning properly.')
@click.argument('KEYLENGTH', type=click.INT, default=2048)
@click.option('-c', '--count', type=click.INT, default=100, help='The amount of tests to be ran.')
@click.option('-l', '--log', is_flag=True, help="Enable logging.", default=False)
@click.option('-lf', '--log-file', help='The file to output logs to. Required if logging is enabled.', required=False)
def test(keylength, count, log, log_file):
	try:
		log_check.init_log_verbosity_check(log, log_file)
	except InvalidOptionsError:
		print('Please use the -lf option to specify the log file.')
		return
	sb = StatusBar(f'Testing RSA encryption and decryption', count)
	FETRSA.test(sb, count, keylength)


def main():
	commands()


commands.add_command(generate)
commands.add_command(test)
commands.add_command(encrypt)
commands.add_command(decrypt)
commands.add_command(sign)
commands.add_command(verify)
commands.add_command(change_password)


if __name__ == '__main__':
	start_time = datetime.datetime.today()
	log_check = LogVerbosityCheck(start_time=start_time, name=f'FET-RSA-2.0({__name__}))')
	atexit.register(log_check.atexitFunc)
	main()

