# aes - Command line utility ![Latest Version]

[Latest Version]: https://img.shields.io/badge/aes-v.1.1.0-green

* AES (Advanced Encryption Standard) implementation written in [Rust](https://www.rust-lang.org/) with [NIST validation tests](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program)
* Compatible with [OpenSSL options](https://www.openssl.org/): -aes-[128,192,256]-[ecb,cbc,ctr], -pbkdf2, -K, -iv
* Written as a personal learning exercise following the algorithm [Rijndael Key Schedule](https://en.wikipedia.org/wiki/Rijndael_key_schedule)
* Shooting for clarity and correctness, not optimization

<HR>

### • byproduct of fun with [cryptopals](https://cryptopals.com/)

<HR>

## Command line usage summary
```
Advanced Encryption Standard with NIST tests
Compatible with OpenSSL options: -aes-[128,192,256]-[ecb,cbc,ctr], -pbkdf2, -K, -iv

Usage: aes [OPTIONS] <--encrypt|--decrypt> <--key <key>|--hexkey <hexkey>> [FILE]

Arguments:
  [FILE]  File to read, treats '-' as standard input

Options:
  -e, --encrypt          Encrypt mode
  -d, --decrypt          Decrypt mode
  -b, --ecb              Cipher is Electronic Codebook
  -c, --cbc              Cipher is Cipher Block Chaining
  -t, --ctr              Cipher is Integer Counter Mode
      --128              Key size
      --192              Key size
      --256              Key size
      --aes-128-ecb      Key size and cipher
      --aes-128-cbc      Key size and cipher
      --aes-128-ctr      Key size and cipher
      --aes-192-ecb      Key size and cipher
      --aes-192-cbc      Key size and cipher
      --aes-192-ctr      Key size and cipher
      --aes-256-ecb      Key size and cipher
      --aes-256-cbc      Key size and cipher
      --aes-256-ctr      Key size and cipher
  -k, --key <key>        Passphrase to create a passkey
  -K, --hexkey <hexkey>  2-byte hex converted to 16,24,32 byte passkey
      --iv <hexiv>       2-byte hex converted to 16 byte iv (or salt with --pbkdf2, --argon2)
  -r, --randiv           Random iv output as 1st block on --encrypt, treat 1st block as iv on --decrypt
      --pbkdf2           Use password-based key derivation function 2 (PBKDF2)
      --argon2           Use password-based key derivation Argon2id
      --iter <iter>      iterations for PBKDF2 [default: 10000]
  -a, --obase64          Output as Base64
  -A, --ibase64          Input is Base64
  -x, --ohex             Output as 2-byte hex
  -X, --ihex             Input is 2-byte hex
      --nopkcs           Prevent a full pad block on --encrypt, skip PKCS#7 pad removal on --decrypt
  -P                     Print the salt/key/iv and exit
  -q, --quiet            Silences warnings regarding short or long passwords
  -h, --help             Print help
  -V, --version          Print version
```

### Build and install into ~/.cargo/bin
```
$> cargo install --path .
```

## NIST [Validation](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program) Vector Tests
```
$> cargo test -r nist_tests
    Finished release [optimized] target(s) in 0.02s
     Running unittests src/main.rs (target/release/deps/aes-029949ef7c38b21b)

running 12 tests
test nist_tests::test_128_cbc_encrypt ... ok
test nist_tests::test_128_cbc_decrypt ... ok
test nist_tests::test_128_ecb_encrypt ... ok
test nist_tests::test_128_ecb_decrypt ... ok
test nist_tests::test_192_cbc_encrypt ... ok
test nist_tests::test_192_cbc_decrypt ... ok
test nist_tests::test_192_ecb_encrypt ... ok
test nist_tests::test_192_ecb_decrypt ... ok
test nist_tests::test_256_cbc_encrypt ... ok
test nist_tests::test_256_cbc_decrypt ... ok
test nist_tests::test_256_ecb_encrypt ... ok
test nist_tests::test_256_ecb_decrypt ... ok

test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
```

<HR>
<HR>

## OpenSSL compatible roundtrip examples

### -pbkdf2 [Password-Based Key Derivation Function-2](https://en.wikipedia.org/wiki/PBKDF2)
```
$> echo "roundtrip hello world" | \
    openssl aes-256-cbc -e -pbkdf2 -k password | \
    aes --aes-256-cbc -d --pbkdf2 -k password
roundtrip hello world


$> echo "roundtrip hello world" | \
    aes --aes-256-cbc -e --pbkdf2 -k password | \
    openssl aes-256-cbc -d -pbkdf2 -k password
roundtrip hello world
```

### The 128-bit examples use a 16-byte password
```
# make a 16 byte password for 128 bit examples
$> echo foo | md5
d3b07384d113edec49eaa6238ad5ff00
```
<HR>

### ECB
```
$> echo "roundtrip hello world" | \
	openssl aes-128-ecb -e -K d3b07384d113edec49eaa6238ad5ff00 | \
	aes --aes-128-ecb -d -K d3b07384d113edec49eaa6238ad5ff00
roundtrip hello world


$> echo "roundtrip hello world" | \
	aes --aes-128-ecb -e -K d3b07384d113edec49eaa6238ad5ff00 | \
	openssl aes-128-ecb -d -K d3b07384d113edec49eaa6238ad5ff00
roundtrip hello world
```

### CBC + IV
```
$> echo "roundtrip hello world" | \
	openssl aes-128-cbc -iv ABCDEF0123456789A0B1C2D3E4F56789 -e -K d3b07384d113edec49eaa6238ad5ff00 | \
	aes --aes-128-cbc --iv=ABCDEF0123456789A0B1C2D3E4F56789 -d -K d3b07384d113edec49eaa6238ad5ff00
roundtrip hello world


$> echo "roundtrip hello world" | \
	aes --aes-128-cbc --iv=ABCDEF0123456789A0B1C2D3E4F56789 -e -K d3b07384d113edec49eaa6238ad5ff00 | \
	openssl aes-128-cbc -iv ABCDEF0123456789A0B1C2D3E4F56789 -d -K d3b07384d113edec49eaa6238ad5ff00
roundtrip hello world
```

### CTR + IV
```
$> echo "roundtrip hello world" | \
   openssl aes-128-ctr -iv ABCDEF0123456789A0B1C2D3E4F56789 -e -K d3b07384d113edec49eaa6238ad5ff00 | \
   aes --aes-128-ctr --iv=ABCDEF0123456789A0B1C2D3E4F56789 -d -K d3b07384d113edec49eaa6238ad5ff00
roundtrip hello world


$> echo "roundtrip hello world" | \
   aes --aes-128-ctr --iv=ABCDEF0123456789A0B1C2D3E4F56789 -e -K d3b07384d113edec49eaa6238ad5ff00 | \
   openssl aes-128-ctr -iv ABCDEF0123456789A0B1C2D3E4F56789 -d -K d3b07384d113edec49eaa6238ad5ff00
roundtrip hello world
```
