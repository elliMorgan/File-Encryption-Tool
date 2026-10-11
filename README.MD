# FET
The <strong>FET</strong> (File Encryption Tool) are a series of encryption programs
written in python with professional CLI, and some GUI. We have

- 3 CLI-based AES programs
- 1 GUI-based AES program
- and 2 CLI-based RSA program


Key derivation is done with PBKDF2. Pycryptodome is required for these programs.

```bash
$ ./FET-AES/FET-AES.py 
Usage: FET-AES.py [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  decrypt
  encrypt

$ ./FET-AES-2.0/FET-AES-2.0.py 
Usage: FET-AES-2.0.py [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  decrypt
  encrypt

$ ./FET-AES-3.0/FET-AES-3.0.py 
 *     *                                                  *     *  *****  ******* ******  
 *  *  * ****** *       ****   ****  *    * ******        *     * *     * *       *     * 
 *  *  * *      *      *    * *    * **  ** *             *     * *       *       *     * 
 *  *  * *****  *      *      *    * * ** * *****         *     *  *****  *****   ******  
 *  *  * *      *      *      *    * *    * *      ***    *     *       * *       *   *   
 *  *  * *      *      *    * *    * *    * *      ***    *     * *     * *       *    *  
  ** **  ****** ******  ****   ****  *    * ******  *      *****   *****  ******* *     * 
                                                   *                                      
Usage: FET-AES-3.0.py [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  decrypt  Decrypt a file or directory.
  encrypt  Encrypt a file or directory.
  test     Ensure AES-CBC is functioning properly.

$ ./FET-RSA/FET-RSA.py 
Usage: FET-RSA.py [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  decrypt
  decryptprivatekey
  encrypt
  encryptprivatekey
  generate
  getkeylength
  pubkey
  sign
  verify
```

I have tried to unify these programs by building them on top of the same code, allowing for generalizations and abstractions (See [my README](https://github.com/elliMorgan/elliMorgan/README.MD)). I have versions in several different directories because I built this project before I understood what Git version control was. 