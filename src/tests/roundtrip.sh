#!/bin/bash

text="roundtrip hello world"

# $> echo "roundtrip hello world" | shasum
# 091789dccca2ae0fe3b52dbfaa685acbeec22f38  -
#
# $> echo "roundtrip hello world" | shasum | cut -c1-40
# 091789dccca2ae0fe3b52dbfaa685acbeec22f38

digest() {
    expected=$1
    computed=`echo "$2" | /usr/bin/shasum | cut -c1-40`
    if [ $expected != $computed ]; then
        echo "failed /usr/bin/shasum"
        echo $expected
        echo $computed
        exit 1
    fi
    echo pass
}

expected=`echo "roundtrip hello world" | /usr/bin/shasum | cut -c1-40`
# ARGON2
for cipher in ecb ctr cbc
do
    for bits in 128 192 256
    do
        digest "$expected" "`echo "$text" | \
            aes --aes-${bits}-${cipher} -e --argon2 -k password | \
            aes --aes-${bits}-${cipher} -d --argon2 -k password`"
    done
done

# PBKDF2
for cipher in ecb ctr cbc
do
    for bits in 128 192 256
    do
        digest "$expected" "`echo "$text" | \
            openssl aes-${bits}-${cipher} -e -pbkdf2 -k password | \
            aes --aes-${bits}-${cipher} -d --pbkdf2 -k password`"

        digest "$expected" "`echo "$text" | \
            aes --aes-${bits}-${cipher} -e --pbkdf2 -k password | \
            openssl aes-${bits}-${cipher} -d -pbkdf2 -k password`"
    done
done

# ECB
for bits in 128 192 256
do
    digest "$expected" "`echo "$text" | \
        openssl enc -aes-${bits}-ecb -e -K d3b07384d113edec49eaa6238ad5ff00 | \
        aes --aes-${bits}-ecb -d -K d3b07384d113edec49eaa6238ad5ff00`"

    digest "$expected" "`echo "$text" | \
        aes --aes-${bits}-ecb -e -K d3b07384d113edec49eaa6238ad5ff00 | \
        openssl enc -aes-${bits}-ecb -d -K d3b07384d113edec49eaa6238ad5ff00`"
done

# CBC + IV
for bits in 128 192 256
do
    digest "$expected" "`echo "$text" | \
        openssl enc -aes-${bits}-cbc -iv ABCDEF0123456789A0B1C2D3E4F56789 -e -K d3b07384d113edec49eaa6238ad5ff00 | \
        aes --aes-${bits}-cbc --iv=ABCDEF0123456789A0B1C2D3E4F56789 -d -K d3b07384d113edec49eaa6238ad5ff00`"

    digest "$expected" "`echo "$text" | \
        aes --aes-${bits}-cbc --iv=ABCDEF0123456789A0B1C2D3E4F56789 -e -K d3b07384d113edec49eaa6238ad5ff00 | \
        openssl enc -aes-${bits}-cbc -iv ABCDEF0123456789A0B1C2D3E4F56789 -d -K d3b07384d113edec49eaa6238ad5ff00`"
done

# CTR + IV
for bits in 128 192 256
do
    digest "$expected" "`echo "$text" | \
       openssl enc -aes-${bits}-ctr -iv ABCDEF0123456789A0B1C2D3E4F56789 -e -K d3b07384d113edec49eaa6238ad5ff00 | \
       aes --aes-${bits}-ctr --iv=ABCDEF0123456789A0B1C2D3E4F56789 -d -K d3b07384d113edec49eaa6238ad5ff00`"

    digest "$expected" "`echo "$text" | \
       aes --aes-${bits}-ctr --iv=ABCDEF0123456789A0B1C2D3E4F56789 -e -K d3b07384d113edec49eaa6238ad5ff00 | \
       openssl enc -aes-${bits}-ctr -iv ABCDEF0123456789A0B1C2D3E4F56789 -d -K d3b07384d113edec49eaa6238ad5ff00`"
done

#
# Base-64 in/out
#

# PBKDF2
digest "$expected" "`echo "$text" | \
    openssl aes-256-cbc -e -a -pbkdf2 -k password | \
    aes --aes-256-cbc -dA --pbkdf2 -k password`"

digest "$expected" "`echo "$text" | \
    aes --aes-256-cbc -ea --pbkdf2 -k password | \
    openssl aes-256-cbc -d -a -pbkdf2 -k password`"

# ECB
digest "$expected" "`echo "$text" | \
	openssl enc -aes-128-ecb -e -a -K d3b07384d113edec49eaa6238ad5ff00 | \
	aes --128 -dbAK d3b07384d113edec49eaa6238ad5ff00`"

digest "$expected" "`echo "$text" | \
	aes --128 --ecb -ea -K d3b07384d113edec49eaa6238ad5ff00 | \
	openssl enc -aes-128-ecb -d -a -K d3b07384d113edec49eaa6238ad5ff00`"

# CBC + IV
digest "$expected" "`echo "$text" | \
	openssl enc -aes-128-cbc -iv ABCDEF0123456789A0B1C2D3E4F56789 -e -a -K d3b07384d113edec49eaa6238ad5ff00 | \
	aes --iv=ABCDEF0123456789A0B1C2D3E4F56789 -dAcK d3b07384d113edec49eaa6238ad5ff00`"

digest "$expected" "`echo "$text" | \
	aes -cea --iv=ABCDEF0123456789A0B1C2D3E4F56789 --hexkey=d3b07384d113edec49eaa6238ad5ff00 | \
	openssl enc -aes-128-cbc -iv ABCDEF0123456789A0B1C2D3E4F56789 -d -a -K d3b07384d113edec49eaa6238ad5ff00`"

# CTR + IV
digest "$expected" "`echo "$text" | \
   openssl enc -aes-128-ctr -iv ABCDEF0123456789A0B1C2D3E4F56789 -e -a -K d3b07384d113edec49eaa6238ad5ff00 | \
   aes --iv=ABCDEF0123456789A0B1C2D3E4F56789 -dtAK d3b07384d113edec49eaa6238ad5ff00`"

digest "$expected" "`echo "$text" | \
   aes --128 --ctr --iv=ABCDEF0123456789A0B1C2D3E4F56789 -ea --hexkey d3b07384d113edec49eaa6238ad5ff00 | \
   openssl enc -aes-128-ctr -iv ABCDEF0123456789A0B1C2D3E4F56789 -d -a -K d3b07384d113edec49eaa6238ad5ff00`"

#
# Binary data
#
expected=`/usr/bin/shasum /bin/ls | cut -c1-40`
computed=`aes --aes-256-cbc -e --pbkdf2 -k password /bin/ls | openssl aes-256-cbc -d -pbkdf2 -k password | /usr/bin/shasum | cut -c1-40`
if [ "$expected" != "$computed" ]; then
    echo "failed /usr/bin/shasum /bin/ls"
    exit 1
else
    echo pass
fi

#
# Binary data, randiv, short password warning
#
echo "Should see 2 password short warnings..."
computed=`aes -crek password /bin/ls | aes -drc --key=password | /usr/bin/shasum | cut -c1-40`
if [ "$expected" != "$computed" ]; then
    echo "failed /usr/bin/shasum /bin/ls"
    exit 1
else
    echo pass
fi

# Quiet warnings
computed=`aes --quiet -crek password /bin/ls | aes -drcq --key=password | /usr/bin/shasum | cut -c1-40`
if [ "$expected" != "$computed" ]; then
    echo "failed /usr/bin/shasum /bin/ls"
    exit 1
else
    echo pass
fi

#
# Binary data, randiv, hex encoding, quiet short password warning
#
computed=`aes -q -crexk password /bin/ls | aes -qX -drc --key=password | /usr/bin/shasum | cut -c1-40`
if [ "$expected" != "$computed" ]; then
    echo "failed /usr/bin/shasum /bin/ls"
    exit 1
else
    echo pass
fi

# salt in openssl -pbkdf2 is the last 8 bytes of 1st block
#
# use aes --vi to set the salt, verify with openssl -P
salt=`echo foo | aes --aes-256-cbc -e --pbkdf2 -k password --iv 0000000000000000abcdef0123456789 | openssl aes-256-cbc -P -d -pbkdf2 -k password | head -1`
if [ "$salt" = "salt=ABCDEF0123456789" ]; then
    echo "pass: setting --pbkdf2 salt to ABCDEF0123456789 using --iv 0000000000000000abcdef0123456789"
else
    echo "failed to set --pbkdf2 salt to ABCDEF0123456789"
    exit 1
fi

# salt in --argon2 is 16 bytes
#
# explicitly supply an iv to show this
salt=`echo foo | aes -P --aes-256-cbc -e --argon2 -k password --iv abcdef01234567899876543210fedcba 2>&1 | grep salt=`
if [ "$salt" = "salt=ABCDEF01234567899876543210FEDCBA" ]; then
    echo "pass: setting --argon2 salt to ABCDEF01234567899876543210FEDCBA using --iv abcdef01234567899876543210fedcba"
else
    echo "failed to set --argon2 salt to ABCDEF01234567899876543210FEDCBA"
    exit 1
fi
