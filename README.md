# aes
AES implementation for personal learning with NIST tests

## Building
### Compile the support library
* $ cd lib
* $ make spotless all

### Compile the command line tool
* $ cd aes
* $ make spotless all

### Tests
<b>$ cd aes</b>

Original crytopals test<br>
<b>$ make spotless test</b><br>

An internal fast test<br>
<b>$ make spotless itest</b><br>

Perl driver feeding NIST tests<br>
<b>$ make spotless nist-test</b><br>

## Command line usage summary
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
 
 ## Example Usage
 I like hex keys so turn a password into hex<br>
 $ <b>echo 'a personal 32 character password' | hexbytes -sn
 6120706572736f6e616c203332206368617261637465722070617373776f7264</b><br>
 
 Encrypt _somefile_ with aes 256 using a random iv and output as hex<br>
 $ <b>aes -256 -encrypt -cbc -randiv -hexkey 6120706572736f6e616c203332206368617261637465722070617373776f7264 -ohex -file somefile > somefile_encrypted.hex</b><br>
 
 Decrypt an input hex file back to its original<br>
 $ <b>aes -256 -decrypt -cbc -randiv -hexkey 6120706572736f6e616c203332206368617261637465722070617373776f7264 -ihex -file somefile_encrypted.hex > somefile.orig</b><br>
