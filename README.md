# aes
AES implementation for personal learning with NIST tests

### Building
# Compile the support library
* $ cd lib
* $ make spotless all

# Compile the command line tool
* $ cd aes
* $ make spotless all

# Tests
* $ cd aes
* # Original crytopals test
* $ make spotless test
* # An internal fast test
* $ make spotless itest
* # Perl driver feeding NIST tests
* $ make spotless nist-test

# Command line usage summary
```Usage: ./aes -[128|192|256] -[ecb|cbc|ctr] -[encrypt|decrypt] -[hex]key passkey
Options:
 -128, -192, -256    key length
 -encrypt, -decrypt  encrypt or decrypt
 -ecb, -cbc, -ctr    block cipher mode, -ecb,-cbc will be PKCS#7 padded
 -key passkey        16,24,32 byte passkey
 -hexkey passkey     2-byte hex characters converted to 16,24,32 bytes
 -iv vector          16 byte initialization vector
 -hexiv vector       2-byte hex characters converted to 16 bytes
 -randiv             system generated "iv" output as first block on -encrypt
                     treat first block as "iv" on -decrypt
 -nopkcs             prevents a "full" pad block being output on -encrypt
                     skip PKCS#7 pad removal on -decrypt
 -[i]base64          treat input as Base64 encoded
 -obase64            output as Base64 encoded
 -[i]hex             treat input as 2-byte hex
 -ohex               output as 2-byte hex
 -file name          file or stdin, filename of - is treated as stdin
 ```
