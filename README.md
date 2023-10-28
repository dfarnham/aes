# aes
AES (Advanced Encryption Standard) implementation with NIST tests


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
# make a 16 byte password from 2-byte hex
$> echo foo | md5
d3b07384d113edec49eaa6238ad5ff00
```

# encrypt (output as Base-64)
```
$> echo "hello world" | aes --cbc --encrypt --obase64 --hexkey d3b07384d113edec49eaa6238ad5ff00
3bYgGt2qlQyTCOH8IWE97w==

# decrypt
$> echo 3bYgGt2qlQyTCOH8IWE97w== | aes --cbc --decrypt --ibase64 --hexkey d3b07384d113edec49eaa6238ad5ff00
hello world
```

## Typical to use a random initialization vector (-r, --randiv)
```
$> echo "hello world" | aes -creaK d3b07384d113edec49eaa6238ad5ff00
cUzxtBeHDxHPplX1I/bcxHtHrEWr10LYCIchlkVki74=

$> echo "hello world" | aes -creaK d3b07384d113edec49eaa6238ad5ff00
1lmZZ7jGlInxAVujRtENtQsKQVTWMdGK6F4/Wp76Phc=
```

## roundtrip
```
$> echo "hello world" | aes -recK d3b07384d113edec49eaa6238ad5ff00 | \
                        aes -rdcK d3b07384d113edec49eaa6238ad5ff00
hello world
```
