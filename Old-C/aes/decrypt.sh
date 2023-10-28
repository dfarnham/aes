#!/bin/sh

passkey='YELLOW SUBMARINE'

aes -128 -ecb -decrypt --key="$passkey" --base64 --file=7.txt | \
aes -128 -ecb -encrypt --key="$passkey"                       | \
aes -128 -ecb -decrypt --key="$passkey"
