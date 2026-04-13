#!/usr/bin/env python3
import os
import getpass
import subprocess
import sys

reset = '\033[39m'
red = '\033[31m'
blue = '\033[34m'
green = '\033[32m'
key_format_prompt = 'Enter format to export keys in(PEM, or DER)'

def print_bad(status, bad_marker='[-]', end='\n'):
    print(f'{red}\r{bad_marker} {reset + status}', end=end)


def print_status(status, status_marker='[*]', end='\n'):
    print(f'{blue}\r{status_marker} {reset + status}', end=end)


def print_good(status, good_marker='[+]', end='\n'):
    print(f'{green}\r{good_marker} {reset + status}', end=end)


def kill_program(status, exit_status=1):
    if exit_status == 1:
        print_bad(status)
    elif exit_status == 0:
        print_status(status)
    print(f'\r{reset}\r    ')
    # elif exit_status == None:
    #     return
    if not isinstance(exit_status, int):
        exit_status = 1
    sys.exit(exit_status)


try:
    import click
    from Cryptodome.Signature import pkcs1_15
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Hash import SHA256
    from Cryptodome.Cipher import PKCS1_OAEP
    from Cryptodome.Math.Numbers import Integer
    from Cryptodome.Math.Primality import generate_probable_prime, test_probable_prime
    from Cryptodome.Random import get_random_bytes
except:
    try:
        print_status('INSTALLING REQUIREMENTS BASED OFF OF "requirements.txt"')
        if os.path.isfile('requirements.txt'):
            subprocess.run(['pip3', 'install', '-r', 'requirements.txt'], capture_output=True)
            print_good('PACKAGES INSTALLED! PLEASE RUN AGAIN!')
            exit(0)

        else:
            raise ValueError
    except ValueError:
        kill_program('UNABLE TO INSTALL REQUIREMENTS!')


def readfile(file):
    print_status(f'READING FILE: {file}')
    try:
        with open(file, 'rb') as buffer:
            contents = buffer.read()
        print_good("COMPLETE!")
        return contents        
    except OSError:
        kill_program(f"ERROR: {file} IS BUSY.")
    except PermissionError:
        kill_program(f'INVALID PERMISSIONS TO READ {file}.')
    except FileNotFoundError:
        kill_program(f'ERROR: FILE NOT FOUND!')
    

def writefile(file, towrite):
    print_status(f'WRITING TO {file}')
    try:
        with open(file, 'wb') as buffer:
            buffer.write(towrite)
        print_good("COMPLETE!")
    except OSError:
        kill_program(f"ERROR: {file} IS BUSY.")
    except PermissionError:
        kill_program(f'INVALID PERMISSIONS TO WRITE TO {file}.')


def decrypt_keys(key):
    while True:
        decrypt_key = getpass.getpass(prompt='ENTER DECRYPTION KEYS FOR RSA PRIVATE KEY: ')
        try:
            key = RSA.import_key(key, decrypt_key)
            return key
        except ValueError:
            print_bad('INCORRECT KEY TO DECRYPT RSA KEY!!')


def get_key_from_file(key_file):
    key = readfile(key_file)
    try:
        key = RSA.import_key(key)
    except ValueError:
        key = decrypt_keys(key)
    return key


def export_keys(key, out_file, format, protection=None, encryption_key=None):
    if format.upper() in ['PEM', 'DER']:
        key = key.export_key(format=format, pkcs=8, protection=protection, passphrase=encryption_key)
        writefile(out_file, key)
    else:
        kill_program(f'{format} IS NOT A VALID FORMAT!!')


@click.group
def functions():
    pass


@click.command()
@click.option('--bits', prompt='Select RSA bit length', help='The length of the rsa key in bits(More than 1024).', type=click.INT, default=2048)
@click.option('--outfile', prompt='Enter out file', help='The file to put the key in.', default='privkey.pem')
@click.option('--format', prompt=key_format_prompt, help='Format of RSA key.', default='PEM')
@click.option('--encrypt', nargs=1, help='Protect the RSA key using one of the following encryption algorithms: DES, ' +\
                                         'AES-128-CBC, AES-192-CBC, and AES-256-CBC', default='AES-256-CBC')
def generate(bits, outfile, encrypt=False, format='PEM', pkcs=8, randfunc=None, e=65537):
    protection = None
    enc_key = None

    if bits < 1024:
        kill_program('KEY-LENGTH MUST MORE THAN 1024.')
    bits = int(bits) if not isinstance(bits, int) else bits
    randfunc = get_random_bytes

    print_status('Calculating d and n...', end='')
    d = n = Integer(1)
    e = Integer(e)
    print('complete')


    while n.size_in_bits() != bits and d < (1 << (bits // 2)):
        # Generate the prime factors of n: p and q.
        # By construciton, their product is always
        # 2^{bits-1} < p*q < 2^bits.
        print_status('Calculating p and q...', end='')
        size_q = bits // 2
        size_p = bits - size_q
        min_p = min_q = (Integer(1) << (2 * size_q - 1)).sqrt()
        if size_q != size_p:
            min_p = (Integer(1) << (2 * size_p - 1)).sqrt()

        def filter_p(candidate):
            return candidate > min_p and (candidate - 1).gcd(e) == 1

        p = generate_probable_prime(exact_bits=size_p,
                                    randfunc=randfunc,
                                    prime_filter=filter_p)

        min_distance = Integer(1) << (bits // 2 - 100)

        def filter_q(candidate):
            return (candidate > min_q and
                    (candidate - 1).gcd(e) == 1 and
                    abs(candidate - p) > min_distance)

        q = generate_probable_prime(exact_bits=size_q,
                                    randfunc=randfunc,
                                    prime_filter=filter_q)

        print('complete')
        print_status('Calculating n...', end='')
        n = p * q
        print('complete')
        print_status('Calculating d...', end='')
        lcm = (p - 1).lcm(q - 1)
        d = e.inverse(lcm)
        print('complete')

    if p > q:
        p, q = q, p

    print_status('Calculating u...', end='')
    u = p.inverse(q)
    print('complete')
    key = RSA.RsaKey(n=n, e=e, d=d, p=p, q=q, u=u)
    print_good('key generated')
    if encrypt.upper()==('DES-EDE3-CBC'):
        protection = 'PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC'
    elif encrypt.upper()==('AES-128-CBC'):
        protection = 'PBKDF2WithHMAC-SHA1AndAES128-CBC'
    elif encrypt.upper()==('AES-192-CBC'):
        protection = 'PBKDF2WithHMAC-SHA1AndAES192-CBC'
    elif encrypt.upper()==('AES-256-CBC'):
        protection = 'PBKDF2WithHMAC-SHA1AndAES256-CBC'
    # elif encrypt!=():
    #     kill_program(f'INVALID ALGORITHM: {encrypt[0]}')
    if protection==None:
        print_status("Encryption algorithm either not valid, or supplied. Proceeding with unprotected private key.")
    if protection!=None:
        enc_key = getpass.getpass(prompt='Enter encryption key: ')
        conf_key = getpass.getpass(prompt='Confirm encryption key: ')
        if enc_key!=conf_key:
            kill_program('UNCONFIRMED ENCRYPTION KEYS!')
            exit(1)
    export_keys(key, out_file=outfile, protection=protection, encryption_key=enc_key, format=format.upper())


@click.command()
@click.option('--keyfile', prompt='Enter the private key file', help='The private key file.')
@click.option('--outfile', prompt='Enter the outfile', help='The file to put the RSA public key in.')
@click.option('--format', prompt=key_format_prompt,help='The format to export the public keys in.')
def pubkey(keyfile, outfile, format):
    key = get_key_from_file(keyfile)
    if not key.has_private():
        kill_program('KEY IS ALREADY PUBLIC KEY!')
        exit(0)
    pub_key = key.public_key()
    export_keys(pub_key, out_file=outfile, format=format)


@click.command()
@click.option('--keyfile', prompt='Enter key file', help='The key file.')
@click.option('--file', prompt='Enter the file to be encrypted', help='The file to be encrypted.')
def encrypt(keyfile, file):
    key = get_key_from_file(keyfile)
    cipher = PKCS1_OAEP.new(key)
    contents = readfile(file)
    print_status('encrypting...')
    encrypted = b''.join( [ cipher.encrypt(contents[i:i+key.size_in_bytes()-42]) for i in range(0, len(contents), key.size_in_bytes()-42) ] )
    writefile(file, encrypted)


@click.command()
@click.option('--file', prompt='Enter the file to decrypt', help='File to decrypt.')
@click.option('--keyfile', prompt='Enter the private key file', help='The private key file.')
def decrypt(file, keyfile):
    key = get_key_from_file(keyfile)
    cipher = PKCS1_OAEP.new(key)
    if key.has_private():
        contents = readfile(file)
        try:
            decrypted = b''.join( [ cipher.decrypt(contents[i:i+key.size_in_bytes()]) for i in range(0, len(contents), key.size_in_bytes()) ] )
        except ValueError:
            kill_program('INCORRECT KEYS TO DECRYPT DATA!!')
        print_good('file decrypted successfully!')
        print_status('writing')
        writefile(file, decrypted)
    else:
        kill_program('UNABLE TO DECRYPT WITH PUBLIC KEYS! PLEASE USE VALID PRIVATE KEY.')


@click.command()
@click.option('--format', prompt=key_format_prompt, help='The format to export the key in')
@click.option('--keyfile', prompt='Enter key file', help='The private key file.')
@click.option('--algorithm', prompt='Enter the algorithm', help='The options are DES-EDE3-CBC, AES-128-CBC, AES-192-CBC, and AES-256-CBC. Recommended is AES-256-CBC')
def encryptPrivateKey(keyfile, algorithm, format):
    key = get_key_from_file(keyfile)
    if not key.has_private():
        kill_program('UNABLE TO ENCRYPT RSA PUBLIC KEYS!')
    if algorithm == 'DES-EDE3-CBC':
        protection = 'PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC'
    elif algorithm == 'AES-128-CBC':
        protection = 'PBKDF2WithHMAC-SHA1AndAES128-CBC'
    elif algorithm == 'AES-192-CBC':
        protection = 'PBKDF2WithHMAC-SHA1AndAES192-CBC'
    elif algorithm == 'AES-256-CBC':
        protection = 'PBKDF2WithHMAC-SHA1AndAES256-CBC'
    else:
        kill_program(f'INVALID ALGORITHM: {algorithm}')
    enc_key = getpass.getpass(prompt='Enter encryption key: ')
    conf_key = getpass.getpass(prompt='Confirm encryption key: ')
    if enc_key!=conf_key:
        kill_program('UNCONFIRMED ENCRYPTION KEYS!')
    export_keys(key, keyfile, format, protection, enc_key)


@click.command()
@click.option('--keyfile', prompt='Enter key file', help='The private key file.')
@click.option('--message', prompt='Enter the message', help='The message to sign(This can be a file, or the message itself).')
@click.option('--outfile', prompt='Enter the outfile', help='The outfile.')
def sign(keyfile, message, outfile):
    if os.path.isfile(message):
        read_msg_from_file = input(f'THERE IS A FILE: {message}. DO YOU WANT TO GET THE MESSAGE FROM THE FILE[Y/n]: ')
        if read_msg_from_file.lower() == 'y':
            message = readfile(message)
        else:
            print_status('Treating message input as message instead of filename.')
    print_status('NOTE FOR SIGN COMMAND: ONLY SHA256 IS AVAILABLE')
    key = get_key_from_file(keyfile)
    if not hasattr(key, '_d'):
        kill_program("UNABLE TO SIGN WITH RSA PUBLIC KEY")
    cipher = pkcs1_15.new(key)
    if isinstance(message, str):
        message = message.encode()
    if not isinstance(message, bytes):
        kill_program(' INCORRECT DATATYPE FOR MESSAGE!')
    print_status('HASHING...')
    hash_obj = SHA256.new(message)
    print_status("SIGNING...")
    signature = cipher.sign(hash_obj)
    writefile(outfile, signature)


@click.command()
@click.option('--keyfile', prompt='Enter the RSA keyfile', help='The RSA keyfile.')
@click.option('--file', prompt='Enter the message file', help='The file containing the message.')
@click.option('--sigfile', prompt='Enter the signature file', help='The file containing the signature.')
def verify(keyfile, file, sigfile):
    key = get_key_from_file(keyfile)
    message = readfile(file)
    signature = readfile(sigfile)
    cipher = pkcs1_15.new(key)
    try:
        cipher.verify(SHA256.new(message), signature)
        print(f'\n##################################################\n################{green}SIGNATURE VERIFIED{reset}################\n##################################################')
        sys.exit(0)
        # print(f'\n##################################################\n################SIGNATURE VERIFIED################\n##################################################')
    except Exception as e:
        print(e)
        kill_program(f'\n##################################################\n################{red}SIGNATURE NOT VERIFIED{reset}############\n##################################################')
        # kill_program(f'\n##################################################\n################SIGNATURE NOT VERIFIED############\n##################################################')


@click.command()
@click.option('--format', prompt=key_format_prompt, help='The format to export the key in')
@click.option('--keyfile', prompt='Enter key file', help='The private key file.')
@click.option('-Y', nargs=0, help='Confirm that you want to decrypt RSA private key(NOT RECOMMENDED!)')
def decryptprivatekey(format, keyfile, y):
    if y == None:
        kill_program('WARNING! USING THIS FUNCTION IS NOT RECOMMENDED! IF YOU REALLY WANT TO DECRYPT THIS KEY, THEN SPECIFY -Y.')
    key = get_key_from_file(keyfile)
    export_keys(key, keyfile, format)


@click.command()
@click.option('--keyfile', help='The file of the RSA key.', prompt='Enter the RSA keyfile')
def getkeylength(keyfile):
    key = get_key_from_file(keyfile)
    bits = key._n.size_in_bits()
    bytes = key.size_in_bytes()
    print_status(f'\nBITS: {bits}\nBYTES: {bytes}')


functions.add_command(generate)
functions.add_command(encrypt)
functions.add_command(decrypt)
functions.add_command(encryptPrivateKey)
functions.add_command(decryptprivatekey)
functions.add_command(pubkey)
functions.add_command(sign)
functions.add_command(verify)
functions.add_command(getkeylength)
functions()
