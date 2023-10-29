# aes

* AES (Advanced Encryption Standard) implementation with NIST tests
* Compatible with [OpenSSL options](https://www.openssl.org/): -aes-[128,192,256]-[ecb,cbc,ctr]

### a byproduct of fun with [cryptopals](https://cryptopals.com/)


## Command line usage summary
```
Advanced Encryption Standard with NIST tests

Usage: aes [OPTIONS] <--encrypt|--decrypt> <--ecb|--cbc|--ctr> <--key <key>|--hexkey <hexkey>> [FILE]

Arguments:
  [FILE]  File to read, treats '-' as standard input

Options:
  -e, --encrypt          Encrypt
  -d, --decrypt          Decrypt
  -b, --ecb              Cipher is Electronic Codebook
  -c, --cbc              Cipher is Cipher Block Chaining
  -t, --ctr              Cipher is Integer Counter Mode
  -A, --ibase64          Input is Base64
  -a, --obase64          Output as Base64
  -X, --ihex             Input is 2-byte hex
  -x, --ohex             Output as 2-byte hex
      --nopkcs           Prevents a full pad block being output on --encrypt, skip PKCS#7 pad removal on --decrypt
  -r, --randiv           Random "iv" output as first block on --encrypt, treat first block as "iv" on --decrypt
      --iv <iv>          16 byte initialization vector
      --hexiv <hexiv>    2-byte hex converted to 16 bytes
  -k, --key <key>        16,24,32 byte passkey
  -K, --hexkey <hexkey>  2-byte hex converted to 16,24,32 byte passkey
  -h, --help             Print help
  -V, --version          Print version
```

## NIST Tests
```
$> cargo test -r
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

## Examples
```
# make a 16 byte password for examples
$> echo foo | md5
d3b07384d113edec49eaa6238ad5ff00
```

## Typical to use a random initialization vector (-r, --randiv)
```
$> echo "hello world" | aes -creK d3b07384d113edec49eaa6238ad5ff00 | \
                        aes -crdK d3b07384d113edec49eaa6238ad5ff00
hello world
```

## OpenSSL compatible

### OpenSSL (ECB) encrypt => aes (ECB) decrypt
```
$> echo "hello world" | openssl enc -aes-128-ecb -e -K d3b07384d113edec49eaa6238ad5ff00 | \
                        aes --ecb -d -K d3b07384d113edec49eaa6238ad5ff00
hello world
```

### aes (ECB) encrypt => OpenSSL (ECB) decrypt
```
$> echo "hello world" | aes --ecb -e -K d3b07384d113edec49eaa6238ad5ff00 | \
                        openssl enc -aes-128-ecb -d -K d3b07384d113edec49eaa6238ad5ff00
hello world
```

### OpenSSL (CBC + IV) encrypt => aes (CBC + IV) decrypt
```
$> echo "hello world" | \
	openssl enc -aes-128-cbc -iv ABCDEF0123456789A0B1C2D3E4F56789 -e -K d3b07384d113edec49eaa6238ad5ff00 | \
	aes --cbc --hexiv=ABCDEF0123456789A0B1C2D3E4F56789 -d -K d3b07384d113edec49eaa6238ad5ff00
hello world
```

### aes (CBC + IV) encrypt => OpenSSL (CBC w+ IV) decrypt
```
$> echo "hello world" | \
	aes --cbc --hexiv=ABCDEF0123456789A0B1C2D3E4F56789 -e -K d3b07384d113edec49eaa6238ad5ff00 | \
	openssl enc -aes-128-cbc -iv ABCDEF0123456789A0B1C2D3E4F56789 -d -K d3b07384d113edec49eaa6238ad5ff00
hello world
```

### OpenSSL (CTR + IV) encrypt => aes (CTR + IV) decrypt
```
$> echo "hello world" | \
   openssl enc -aes-128-ctr -iv ABCDEF0123456789A0B1C2D3E4F56789 -e -K d3b07384d113edec49eaa6238ad5ff00 | \
   aes --ctr --hexiv=ABCDEF0123456789A0B1C2D3E4F56789 -d -K d3b07384d113edec49eaa6238ad5ff00
hello world
```

### aes (CTR + IV) encrypt => OpenSSL (CTR + IV) decrypt
```
$> echo "hello world" | \
   aes --ctr --hexiv=ABCDEF0123456789A0B1C2D3E4F56789 -e -K d3b07384d113edec49eaa6238ad5ff00 | \
   openssl enc -aes-128-ctr -iv ABCDEF0123456789A0B1C2D3E4F56789 -d -K d3b07384d113edec49eaa6238ad5ff00
hello world
```
