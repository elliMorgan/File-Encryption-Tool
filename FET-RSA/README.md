FET-RSA is a cmdline file encryption tool that uses the pycryptodomex
library in order to encrypt private files
and keep them away from prying eyes. It can export and protect keys using
256 bit AES, or DES. 


The FET-RSA accepts keylengths in 1024 bit, 2048 bit, 
and 4096 bit. The size of the file is irrelevant, as the FET-RSA breaks
the file down into chunks at the length of the keysize in bytes -42. This
means that it bypasses the 'maximum message length' nuisance.


This means that it is no longer required go through the painstaiking process
of generateing an aes key, encrypting the file, generating an rsa key, encryping
the aes key with the rsa key, and exporting the rsa key. The FET-RSA does all encryption
with the rsa key.


FET-RSA-GUI WILL BE COMING OUT SOON!!!
