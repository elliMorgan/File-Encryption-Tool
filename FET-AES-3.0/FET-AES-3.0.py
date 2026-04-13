#!/usr/bin/env python3


import atexit
import click
import struct
import threading
import getpass
import os
import datetime
# import queue
import base64
# import time
import sys


fet_module_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
sys.path.append(fet_module_dir)
fet_module_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../FET"))
sys.path.append(fet_module_dir)


from FET import InvalidKeyLengthError, InvalidPaddingError, MissingTagError, AlreadyEncryptedError, InvalidOptionsError, FET, LogVerbosityCheck, StatusBar, SHA256, get_random_bytes, PBKDF2, FETAESCBCCORE, Status


class FETAESCBC(FET.SymmetricFET):
	def __init__(self, key, encryptFunc=FETAESCBCCORE.encrypt, decryptFunc=FETAESCBCCORE.decrypt, tag=b'P\x1cK\x81kl}\xde\xc8\xc8NSn\xe0o\xe2i\x05AI\xabQs\xd9:\xd5t%\x93\x8e\xd7>'):
		super().__init__(key, encryptFunc, decryptFunc, "AES-CBC", tag)


	def encrypt(self, data, dkLen=32, pbkdf2_count=1000000, salt_length=64, hmac_hash_module=SHA256):
		super().check_tag(data)
		salt = get_random_bytes(salt_length)
		salted_key = PBKDF2(self._key, salt, dkLen, pbkdf2_count, hmac_hash_module=hmac_hash_module)
		return super().encrypt(struct.pack('<I', dkLen) + struct.pack('<I', pbkdf2_count) + struct.pack('<I', salt_length) + self.encryptFunc(data, salted_key) + salt)


	def decrypt(self, data, hmac_hash_module=SHA256):
		data = super().decrypt(data)
		dkLen = struct.unpack('<I', data[:4])[0]
		data = data[4:]
		pbkdf2_count = struct.unpack('<I', data[:4])[0]
		data = data[4:]
		salt_length = struct.unpack('<I', data[:4])[0]
		data = data[4:]
		salt = data[-salt_length:]
		data = data[:-salt_length]
		salted_key = PBKDF2(self._key, salt, dkLen, pbkdf2_count, hmac_hash_module=hmac_hash_module)
		return self.decryptFunc(data, salted_key)


	@staticmethod
	def test(sb, times=100):
		log_check.log_with_date_and_time_if_v(f"Running {times} encryption and decryption tests on AES-CBC.")
		for i in range(times):
			log_check.log_with_date_and_time_if_v(f"Running test {i+1}/{times}.")
			key = get_random_bytes(10)
			data = get_random_bytes(10)
			log_check.log_with_date_and_time_if_v(f"key: {key}")
			log_check.log_with_date_and_time_if_v(f"data: {data}")
			f = FETAESCBC(key)
			encrypted = f.encrypt(data);
			decrypted = f.decrypt(encrypted)
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


def get_passkey(verify, prompt='Password: '):
	passkey = getpass.getpass(prompt=prompt)
	if verify:
		test = getpass.getpass("Please enter password again: ")
		if test == passkey:
			return passkey
		else:
			Status.status_bad('The passwords don\'t match.')
			sys.exit(1)


@click.group()
def commands():
	pass


def encryptFilesTh(fetAesCbc, files, sb, dkLen, pbkdf2_count, salt_length):
	i = 0
	totalFiles = len(files)
	while len(files) > 0:
		i+=1
		file = files.pop(0)
		try:
			with open(file, 'rb') as handle:
				data = handle.read()
			encrypted_data = fetAesCbc.encrypt(data, dkLen, pbkdf2_count, salt_length)
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


def walkDirs(files):
	for f in files:
		if os.path.isdir(f):
			for root, folder, walkFiles in os.walk(f):
				for walkFile in walkFiles:
					files.append(os.path.join(root, walkFile))
			files.remove(f)


def encryptFiles(key, files, sb, dkLen, pbkdf2_count, salt_length, nThreads):
	threads = []
	walkDirs(files)
	log_check.log_with_date_and_time_if_v(f"Encrypting %d files with %d threads, %d keylength, %d PBKDF2 iterations and a %d byte salt length, "%(len(files), nThreads, dkLen, pbkdf2_count, salt_length))
	fetAesCbc = FETAESCBC(key)
	for i in range(nThreads):
		t = threading.Thread(target=encryptFilesTh, args=(fetAesCbc, files, sb, dkLen, pbkdf2_count, salt_length))
		threads.append(t)
	for i in range(nThreads):
		log_check.log_with_date_and_time_if_v(f"Started thread {i+1}/{nThreads}")
		threads[i].start()
	for i in range(nThreads):
		log_check.log_with_date_and_time_if_v(f"Joining thread {i+1}/{nThreads}")
		threads[i].join()
	# print(files)


def decryptFilesTh(fetAesCbc, files, sb):
	i = 0
	totalFiles = len(files)
	while len(files) > 0:
		i+=1
		file = files.pop(0)
		try:
			with open(file, 'rb') as handle:
				data = handle.read()
			encrypted_data = fetAesCbc.decrypt(data)
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


def decryptFiles(key, files, sb, nThreads):
	threads = []
	walkDirs(files)
	log_check.log_with_date_and_time_if_v(f"Decrypting %d files with %d threads"%(len(files), nThreads))
	fetAesCbc = FETAESCBC(key)
	for i in range(nThreads):
		t = threading.Thread(target=decryptFilesTh, args=(fetAesCbc, files, sb))
		threads.append(t)
	for i in range(nThreads):
		log_check.log_with_date_and_time_if_v(f"Started thread {i+1}/{nThreads}")
		threads[i].start()
	for i in range(nThreads):
		log_check.log_with_date_and_time_if_v(f"Joining thread {i+1}/{nThreads}")
		threads[i].join()


@click.command(help='Encrypt a file or directory.')
@click.argument('files', type=click.Path(exists=True), nargs=-1, required=True)
@click.option('-d', '--dklen', help='The length of the salted key in bits.', type=click.Choice(['128', '192', '256']), default='256')
@click.option('-pc', '--PBKDF2-count', help='The number of iterations for PBKDF2.', type=click.INT, default=5000000)
@click.option('-sl', '--salt-length', help='The length of the salt for PBKDF2.', type=click.INT, default=64)
@click.option('-nt', '--n-threads', help='The number of threads(creating more threads typically make issues with the status bar).', type=click.INT, default=1)
@click.option('-l', '--log', is_flag=True, help="Enable logging.", default=False)
@click.option('-lf', '--log-file', help='The file to output logs to. Required if logging is enabled.', required=False)
def encrypt(files, dklen, pbkdf2_count, salt_length, n_threads, log, log_file):
	try:
		log_check.init_log_verbosity_check(log, log_file)
	except InvalidOptionsError:
		print('Please use the -lf option to specify the log file.')
		return
	key = get_passkey(True)
	sb = StatusBar('Encrypting files(%d total)...'%(len(files)), len(files))
	encryptFiles(key, list(files), sb, int(int(dklen)/8), pbkdf2_count, salt_length, n_threads)


@click.command(help='Decrypt a file or directory.')
@click.argument('files', type=click.Path(exists=True), nargs=-1, required=True)
@click.option('-nt', '--n-threads', help='The number of threads(creating more threads typically make issues with the status bar).', type=click.INT, default=1)
@click.option('-l', '--log', is_flag=True, help="Enable logging.", default=False)
@click.option('-lf', '--log-file', help='The file to output logs to. Required if logging is enabled.', required=False)
def decrypt(files, n_threads, log, log_file):
	try:
		log_check.init_log_verbosity_check(log, log_file)
	except InvalidOptionsError:
		print('Please use the -lf option to specify the log file.')
		return
	key = getpass.getpass()
	sb = StatusBar('Decrypting files(%d total)...'%(len(files)), len(files))
	decryptFiles(key, list(files), sb, n_threads)


@click.command(help='Ensure AES-CBC is functioning properly.')
@click.option('-c', '--count', type=click.INT, default=100, help='The amount of tests to be ran.')
@click.option('-l', '--log', is_flag=True, help="Enable logging.", default=False)
@click.option('-lf', '--log-file', help='The file to output logs to. Required if logging is enabled.', required=False)
def test(count, log, log_file):
	try:
		log_check.init_log_verbosity_check(log, log_file)
	except InvalidOptionsError:
		print('Please use the -lf option to specify the log file.')
		return
	sb = StatusBar(f'Testing AES-CBC encryption and decryption', count)
	FETAESCBC.test(sb, count)


def main():
	commands()


commands.add_command(encrypt)
commands.add_command(decrypt)
commands.add_command(test)


if __name__ == '__main__':
	print(''' *     *                                                  *     *  *****  ******* ******  
 *  *  * ****** *       ****   ****  *    * ******        *     * *     * *       *     * 
 *  *  * *      *      *    * *    * **  ** *             *     * *       *       *     * 
 *  *  * *****  *      *      *    * * ** * *****         *     *  *****  *****   ******  
 *  *  * *      *      *      *    * *    * *      ***    *     *       * *       *   *   
 *  *  * *      *      *    * *    * *    * *      ***    *     * *     * *       *    *  
  ** **  ****** ******  ****   ****  *    * ******  *      *****   *****  ******* *     * 
                                                   *                                      ''')
	start_time = datetime.datetime.today()
	log_check = LogVerbosityCheck(start_time=start_time, name=f'FET-AES-3.0{__name__}')
	atexit.register(log_check.atexitFunc)
	main()

