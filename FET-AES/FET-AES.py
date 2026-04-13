#!/usr/bin/env python3
import os
import getpass
import subprocess
import sys
import time
import base64
import binascii


class FET:
    pass


class prints(FET):
    reset = '\033[39m'
    red = '\033[31m'
    blue = '\033[34m'
    green = '\033[32m'
    # print(list(os.environ))
    
    def __init__(self, v=False):
        if 'win' in sys.platform.lower() and not 'TERM' in os.environ:
            # print('resetting colors')
            self.v = v
            self.red = ''
            self.reset = ''
            self.blue = ''
            self.green = ''
    # print('TERM' in list(os.environ))
    
    def print_bad(self, status, bad_marker='[-]', end='\n'):
        if self.v:
            print(f'{self.red}\r{bad_marker} {self.reset + status}', end=end)
    
    
    def print_status(self, status, status_marker='[*]', end='\n'):
        if self.v:
            print(f'{self.blue}\r{status_marker} {self.reset + status}', end=end)
    
    
    def print_good(self, status, good_marker='[+]', end='\n'):
        if self.v:
            print(f'{self.green}\r{good_marker} {self.reset + status}', end=end)


printer = prints()


class FETAPI(FET):
    def kill_program(status, exit_status=1):
        # printer = prints()
        printer.v = True
        if exit_status == 1:
            printer.print_bad(status)
        elif exit_status == 0:
            printer.print_status(status)
        print(f'\r{printer.reset}\r    ')
        if not isinstance(exit_status, int):
            exit_status = 1
        sys.exit(exit_status)


    def get_key(confirm: bool = True):
        key = getpass.getpass(prompt='ENTER THE KEY: ').encode()
        if not confirm:
            return key
        conf_key = getpass.getpass(prompt='CONFIRM THE KEY: ').encode()
        if key != conf_key:
            FETAPI.kill_program('THE KEYS DON\'T MATCH!')
        else:
            printer.print_good('Matching keys!')
        return key


try:
    import click
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.Padding import pad, unpad
    from Cryptodome.Protocol.KDF import PBKDF2
    from Cryptodome import Hash
    from Cryptodome.Hash import *
    from Cryptodome.Random import get_random_bytes
except ModuleNotFoundError:
    try:
        printer.v = True
        printer.print_status('INSTALLING REQUIREMENTS BASED OFF OF "requirements.txt"')
        if os.path.isfile('requirements.txt'):
            subprocess.run(['pip', 'install', '-r', 'requirements.txt'], stderr=subprocess.PIPE,
                           stdout=subprocess.PIPE)
            printer.print_good('PACKAGES INSTALLED! PLEASE RUN AGAIN!')
            exit(0)

        else:
            raise ValueError
    except ValueError:
        FETAPI.kill_program('UNABLE TO INSTALL REQUIREMENTS!')
printer.v = False


class fileApi(FETAPI):
    def readfile(file: str, kill_if_failed: bool=True):
        printer.print_status(f'READING FILE: {file}')
        try:
            with open(file, 'rb') as buffer:
                contents = buffer.read()
            printer.print_good("COMPLETE!")
            return contents
        except PermissionError:
            if kill_if_failed:
                FETAPI.kill_program(f'INVALID PERMISSIONS TO READ {file}.')
            printer.print_bad(f'INVALID PERMISSIONS TO READ {file}.')
        except FileNotFoundError:
            if kill_if_failed:
                FETAPI.kill_program(f'ERROR: FILE NOT FOUND!')
            printer.print_bad(f'ERROR: FILE NOT FOUND!')
        except OSError:
            if kill_if_failed:
                FETAPI.kill_program(f"ERROR: {file} IS BUSY.")
            printer.print_bad(f"ERROR: {file} IS BUSY.")


    def writefile(file: str, towrite: bytes, kill_if_failed: bool=True):
        printer.print_status(f'WRITING TO {file}')
        try:
            with open(file, 'wb') as buffer:
                buffer.write(towrite)
            printer.print_good("COMPLETE!")
        except PermissionError:
            if kill_if_failed:
                FETAPI.kill_program(f'INVALID PERMISSIONS TO WRITE TO {file}.')
            else:
                printer.print_bad(f'INVALID PERMISSIONS TO WRITE TO {file}.')
        except OSError:
            if kill_if_failed:
                FETAPI.kill_program(f"ERROR: {file} IS BUSY.")
            else:
                printer.print_bad(f"ERROR: {file} IS BUSY.")


@click.group()
def commands():
    pass



available_hashes = [
    'MD2',
    'MD4',
    'MD5',
    'RIPEMD160',
    'SHA1',
    'SHA224',
    'SHA256',
    'SHA384',
    'SHA512'
]


class FETAESApi(FETAPI):
    def encrypt_contents(key: bytes, contents: bytes) -> bytes:
        printer.print_status("Encrypting data...")
        cipher = AES.new(key, AES.MODE_CBC, iv=os.urandom(16))
        printer.print_status("Generated IV...")
        encrypted = cipher.encrypt(pad(contents, AES.block_size))
        printer.print_good('ENCRYPTION COMPLETED!')
        return cipher.iv + encrypted


    def decrypt_file(filename: str, key: bytes, kill_if_failed: bool = True, hash_module=SHA512) -> bytes:
        pbkdf2_failed = f'{filename}: PBKDF2 FAILED!'
        decryption_incorrect = f'{filename}: DECRYPTION INCORRECT!!'
        not_encrypted = f'{filename}: not encrypted.'
        contents = fileApi.readfile(filename, kill_if_failed)
        try:
            contents = base64.urlsafe_b64decode(contents)
        except binascii.Error:
            if not kill_if_failed:
                printer.print_bad(not_encrypted)
                return contents
            else:
                FETAPI.kill_program(not_encrypted)
        salt = contents[-32:]
        if len(salt)!=32:
            if kill_if_failed:
                printer.print_bad(not_encrypted)
                return
            FETAPI.kill_program(not_encrypted)
        contents = contents[:-32]
        printer.print_status('Salting key with PBKDF2(This may take a while depending on the hashing algorithm)')
        try:
            key = PBKDF2(key, salt, 32, count=100000, hmac_hash_module=hash_module)
        except binascii.Error:
           if kill_if_failed:
                printer.print_bad(pbkdf2_failed)
                return
                FETAPI.kill_program(pbkdf2_failed)
        printer.print_good(f'Key salted with PBKDF2.')

        iv = contents[:16]
        if len(iv) < 16 and kill_if_failed:
            FETAPI.kill_program('ERROR: MISSING IV! BE SURE THAT THIS IS THE ENCRYPTED FILE THAT YOU WANT TO DECRYPT!')
        elif len(iv)<16:
            return contents
        printer.print_status('DERIVED IV')
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        try:
            decrypted = cipher.decrypt(contents[16:])
            decrypted = unpad(decrypted, AES.block_size)
        except ValueError:
            if kill_if_failed:
                FETAPI.kill_program(decryption_incorrect)
            else:
                v = printer.v
                printer.v = True
                printer.print_bad(decryption_incorrect)
                printer.v = v
                return contents
        printer.print_good(f'{filename}: DECRYPTION SUCCEEDED.')
        return decrypted


    def encrypt_files(files, hash_module, plaintext_key, iterate=False, several_files=None):
        if several_files is None:
            several_files = len(files)!=1
        for file in files:
            if os.path.isdir(file) and not iterate:
                printer.print_bad(f'{file}: Is not a file.')
                continue
            elif os.path.isdir(file):
                printer.print_status(f'Recursing into {file}.')
                FETAESApi.encrypt_files([os.path.join(file, entry.name) for entry in os.scandir(file)], hash_module, plaintext_key, iterate, True)
                printer.print_good(f'Recursion into {file} complete.')
                time.sleep(0.5)
                continue
            salt = get_random_bytes(32)
            printer.print_status('Salting key with PBKDF2(This may take a while depending on the hash algorithm)')
            key = PBKDF2(plaintext_key, salt, 32, count=100000, hmac_hash_module=hash_module)
            printer.print_good(f'Key salted with PBKDF2.')
            contents = fileApi.readfile(file, not several_files)
            if contents==None:
                continue
            # time.sleep(0.5)
            # time.sleep(0.5)
            encrypted = FETAESApi.encrypt_contents(key, contents)
            # time.sleep(0.5)
            encoded_ciphertext = base64.urlsafe_b64encode(encrypted + salt)
            fileApi.writefile(file, encoded_ciphertext, not several_files)
            # time.sleep(0.5)
    
    
    def decrypt_files(files, hash_module, plaintext_key, iterate=False, several_files=None):
        if several_files is None:
            several_files = len(files)!=1
        for file in files:
            if os.path.isdir(file) and not iterate:
                printer.print_status(f'{file}: Is not a file.')
                continue
            elif os.path.isdir(file):
                printer.print_status(f'Recursing into {file}.')
                FETAESApi.decrypt_files([os.path.join(file, entry.name) for entry in os.scandir(file)], hash_module, plaintext_key, iterate, True)
                printer.print_good(f'Recursion into {file} complete.')
                time.sleep(0.5)
                continue
#            try:
#                contents = base64.urlsafe_b64decode(fileApi.readfile(file, not several_files))
#            except binascii.Error:
#                if several_files:
#                    printer.print_bad(not_encrypted)
#                    continue
#                FETAPI.kill_program(not_encrypted)
            # except TypeError:
            # print('decoded')
            # time.sleep(0.5)
            # time.sleep(0.5)
            decrypted = FETAESApi.decrypt_file(file, plaintext_key, not several_files, hash_module)
            if decrypted == None:
                continue
            # time.sleep(0.5)
            fileApi.writefile(file, decrypted, not several_files)
            # time.sleep(0.5)


    @click.command()
    @click.argument('files', nargs=-1, type=click.Path(exists=True))
    @click.option('--hash-algorithm', default='SHA512',
                  help=f"The hash algorithm to use for PBKDF2. Available:\n" + '\n'.join(available_hashes))
    @click.option('-r', is_flag=True, help='Flag to indicate recursion through folders.')
    @click.option('-v', is_flag=True, help='Flag to indicate verbose mode.')
    def encrypt(files: tuple, hash_algorithm: str, r, v):
        printer.v = v
        try:
            hash_module = getattr(Hash, hash_algorithm)
            if not hasattr(hash_module, 'digest_size') or not hash_algorithm in available_hashes:
                raise AttributeError
        except AttributeError:
            printer.print_bad(f'INVALID HASHING ALGORITHM: {hash_algorithm.upper()}')
            FETAPI.kill_program(
                f"Valid algorithms:\n" + '\n'.join(available_hashes), 0)
        plaintext_key = FETAPI.get_key()
        FETAESApi.encrypt_files(files, hash_module, plaintext_key, r)


    # remove_hashes()
    @click.command()
    @click.argument('files', nargs=-1, type=click.Path(exists=True))
    @click.option('--hash-algorithm', default='SHA512',
                  help=f'The algorithm to use for PBKDF2. Available:\n'+'\n'.join(available_hashes))
    @click.option('-r', is_flag=True, help='Flag to indicate recursion through folders.')
    @click.option('-v', is_flag=True, help='Flag to indicate verbose mode.')
    def decrypt(files: tuple, hash_algorithm: str, r, v):
        printer.v = v
        #exit()
        try:
            hash_module = getattr(Hash, hash_algorithm)
            if not hasattr(hash_module, 'digest_size') or not hash_algorithm in available_hashes:
                raise AttributeError
        except AttributeError:
            printer.print_bad(f'INVALID HASHING ALGORITHM: {hash_algorithm.upper()}')
            FETAPI.kill_program(
                f"Valid algorithms: \n" + '\n'.join(available_hashes), 0)
        plaintext_key = FETAPI.get_key(False)
        FETAESApi.decrypt_files(files, hash_module, plaintext_key, r)


commands.add_command(FETAESApi.decrypt)
commands.add_command(FETAESApi.encrypt)
if __name__ == '__main__':
    commands()
