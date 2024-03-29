#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#if defined(__linux__)
#  define ntohll(x) htobe64(x)
#endif

typedef unsigned char uchar;

#define ENCRYPT 0
#define DECRYPT 1

// Electronic Codebook (ECB)
#define ECB 0

// Cipher Block Chaining (CBC)
#define CBC 1

// CTR - Integer Counter Mode
#define CTR 2

/****************************************************
 *
 * https://cryptopals.com/sets/1/challenges/7
 *
 * 128,192,256 bit AES ECB/CBC encryption library
 * written as a personal learning exercise using
 * the algorithm described at:
 * https://en.wikipedia.org/wiki/Rijndael_key_schedule
 *****************************************************/

/*
 * Local functions
 */
uchar   rcon                (uchar);
uchar   sbox                (uchar);
uchar   invSbox             (uchar);
uchar   T2                  (uchar);
uchar   T3                  (uchar);
uchar   T9                  (uchar);
uchar   T11                 (uchar);
uchar   T13                 (uchar);
uchar   T14                 (uchar);
void    mixColumns          (uchar[4][4], uchar);
void    mixColumn           (uchar[4]);
void    invMixColumn        (uchar[4]);
void    rotateLeft          (uchar[4]);
void    rotateRight         (uchar[4]);
void    keycore             (uchar[4], int);
void    keyExpansion        (int, int, uchar[], const uchar *);
void    addRoundKey         (uchar[4][4], uchar[], int, int, uchar);
void    subBytes            (uchar[4][4], uchar);
void    shiftRows           (uchar[4][4], uchar);
void    aes128Encrypt       (const uchar *, const uchar *, int, int, const uchar *, uchar *);
void    aes128Decrypt       (const uchar *, const uchar *, int, int, const uchar *, uchar *);
void    aes192Encrypt       (const uchar *, const uchar *, int, int, const uchar *, uchar *);
void    aes192Decrypt       (const uchar *, const uchar *, int, int, const uchar *, uchar *);
void    aes256Encrypt       (const uchar *, const uchar *, int, int, const uchar *, uchar *);
void    aes256Decrypt       (const uchar *, const uchar *, int, int, const uchar *, uchar *);
void    aesEncrypt          (int, int, const uchar *, const uchar *, int, int, const uchar *, uchar *);
void    aesDecrypt          (int, int, const uchar *, const uchar *, int, int, const uchar *, uchar *);
void    aesEncryptCTR       (int, int, const uchar *, const uchar *, int, const uchar *, uchar *);


/* ---------------------------------------------------------------- */

void
aes128Encrypt(const uchar *passkey, const uchar *data, int nbytes, int mode, const uchar *iv, uchar *output) {
    if (mode == CTR) {
        aesEncryptCTR(128, 176, passkey, data, nbytes, iv, output);
    } else {
        aesEncrypt(128, 176, passkey, data, nbytes, mode, iv, output);
    }
}
void
aes192Encrypt(const uchar *passkey, const uchar *data, int nbytes, int mode, const uchar *iv, uchar *output) {
    if (mode == CTR) {
        aesEncryptCTR(192, 208, passkey, data, nbytes, iv, output);
    } else {
        aesEncrypt(192, 208, passkey, data, nbytes, mode, iv, output);
    }
}
void
aes256Encrypt(const uchar *passkey, const uchar *data, int nbytes, int mode, const uchar *iv, uchar *output) {
    if (mode == CTR) {
        aesEncryptCTR(256, 240, passkey, data, nbytes, iv, output);
    } else {
        aesEncrypt(256, 240, passkey, data, nbytes, mode, iv, output);
    }
}


void
aes128Decrypt(const uchar *passkey, const uchar *data, int nbytes, int mode, const uchar *iv, uchar *output) {
    if (mode == CTR) {
        aesEncryptCTR(128, 176, passkey, data, nbytes, iv, output);
    } else {
        aesDecrypt(128, 176, passkey, data, nbytes, mode, iv, output);
    }
}
void
aes192Decrypt(const uchar *passkey, const uchar *data, int nbytes, int mode, const uchar *iv, uchar *output) {
    if (mode == CTR) {
        aesEncryptCTR(192, 208, passkey, data, nbytes, iv, output);
    } else {
        aesDecrypt(192, 208, passkey, data, nbytes, mode, iv, output);
    }
}
void
aes256Decrypt(const uchar *passkey, const uchar *data, int nbytes, int mode, const uchar *iv, uchar *output) {
    if (mode == CTR) {
        aesEncryptCTR(256, 240, passkey, data, nbytes, iv, output);
    } else {
        aesDecrypt(256, 240, passkey, data, nbytes, mode, iv, output);
    }
}


uchar
rcon(uchar c) {
    static uchar table[256] = {
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
        0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
        0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
        0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
        0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
        0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
        0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
        0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
        0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
        0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
        0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
        0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
        0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
        0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
        0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
    };
    return table[c];
}

uchar
sbox(uchar c) {
    static uchar table[16][16] = {
        { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, },
        { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, },
        { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, },
        { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, },
        { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, },
        { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, },
        { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, },
        { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, },
        { 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, },
        { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, },
        { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, },
        { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, },
        { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, },
        { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, },
        { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, },
        { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16, }
    };
    return(table[c >> 4][c & 0x0f]);
}

uchar
invSbox(uchar c) {
    static uchar table[16][16] = {
        { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb },
        { 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb },
        { 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e },
        { 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 },
        { 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 },
        { 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 },
        { 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 },
        { 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b },
        { 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 },
        { 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e },
        { 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b },
        { 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 },
        { 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f },
        { 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef },
        { 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 },
        { 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d }
    };
    return(table[c >> 4][c & 0x0f]);
}

uchar
T2(uchar c) {
    static uchar table[256] = {
        0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e, 
        0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e, 
        0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e, 
        0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e, 
        0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e, 
        0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe, 
        0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde, 
        0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe, 
        0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05, 
        0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25, 
        0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55, 0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45, 
        0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65, 
        0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95, 0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85, 
        0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5, 0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5, 
        0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5, 
        0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5
    };
    return table[c];
}

uchar
T3(uchar c) {
    static uchar table[256] = {
        0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09, 0x18, 0x1b, 0x1e, 0x1d, 0x14, 0x17, 0x12, 0x11, 
        0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39, 0x28, 0x2b, 0x2e, 0x2d, 0x24, 0x27, 0x22, 0x21, 
        0x60, 0x63, 0x66, 0x65, 0x6c, 0x6f, 0x6a, 0x69, 0x78, 0x7b, 0x7e, 0x7d, 0x74, 0x77, 0x72, 0x71, 
        0x50, 0x53, 0x56, 0x55, 0x5c, 0x5f, 0x5a, 0x59, 0x48, 0x4b, 0x4e, 0x4d, 0x44, 0x47, 0x42, 0x41, 
        0xc0, 0xc3, 0xc6, 0xc5, 0xcc, 0xcf, 0xca, 0xc9, 0xd8, 0xdb, 0xde, 0xdd, 0xd4, 0xd7, 0xd2, 0xd1, 
        0xf0, 0xf3, 0xf6, 0xf5, 0xfc, 0xff, 0xfa, 0xf9, 0xe8, 0xeb, 0xee, 0xed, 0xe4, 0xe7, 0xe2, 0xe1, 
        0xa0, 0xa3, 0xa6, 0xa5, 0xac, 0xaf, 0xaa, 0xa9, 0xb8, 0xbb, 0xbe, 0xbd, 0xb4, 0xb7, 0xb2, 0xb1, 
        0x90, 0x93, 0x96, 0x95, 0x9c, 0x9f, 0x9a, 0x99, 0x88, 0x8b, 0x8e, 0x8d, 0x84, 0x87, 0x82, 0x81, 
        0x9b, 0x98, 0x9d, 0x9e, 0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86, 0x8f, 0x8c, 0x89, 0x8a, 
        0xab, 0xa8, 0xad, 0xae, 0xa7, 0xa4, 0xa1, 0xa2, 0xb3, 0xb0, 0xb5, 0xb6, 0xbf, 0xbc, 0xb9, 0xba, 
        0xfb, 0xf8, 0xfd, 0xfe, 0xf7, 0xf4, 0xf1, 0xf2, 0xe3, 0xe0, 0xe5, 0xe6, 0xef, 0xec, 0xe9, 0xea, 
        0xcb, 0xc8, 0xcd, 0xce, 0xc7, 0xc4, 0xc1, 0xc2, 0xd3, 0xd0, 0xd5, 0xd6, 0xdf, 0xdc, 0xd9, 0xda, 
        0x5b, 0x58, 0x5d, 0x5e, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46, 0x4f, 0x4c, 0x49, 0x4a, 
        0x6b, 0x68, 0x6d, 0x6e, 0x67, 0x64, 0x61, 0x62, 0x73, 0x70, 0x75, 0x76, 0x7f, 0x7c, 0x79, 0x7a, 
        0x3b, 0x38, 0x3d, 0x3e, 0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26, 0x2f, 0x2c, 0x29, 0x2a, 
        0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10, 0x15, 0x16, 0x1f, 0x1c, 0x19, 0x1a
    };
    return table[c];
}

uchar
T9(uchar c) {
    static uchar table[256] = {
        0x00, 0x09, 0x12, 0x1b, 0x24, 0x2d, 0x36, 0x3f, 0x48, 0x41, 0x5a, 0x53, 0x6c, 0x65, 0x7e, 0x77, 
        0x90, 0x99, 0x82, 0x8b, 0xb4, 0xbd, 0xa6, 0xaf, 0xd8, 0xd1, 0xca, 0xc3, 0xfc, 0xf5, 0xee, 0xe7, 
        0x3b, 0x32, 0x29, 0x20, 0x1f, 0x16, 0x0d, 0x04, 0x73, 0x7a, 0x61, 0x68, 0x57, 0x5e, 0x45, 0x4c, 
        0xab, 0xa2, 0xb9, 0xb0, 0x8f, 0x86, 0x9d, 0x94, 0xe3, 0xea, 0xf1, 0xf8, 0xc7, 0xce, 0xd5, 0xdc, 
        0x76, 0x7f, 0x64, 0x6d, 0x52, 0x5b, 0x40, 0x49, 0x3e, 0x37, 0x2c, 0x25, 0x1a, 0x13, 0x08, 0x01, 
        0xe6, 0xef, 0xf4, 0xfd, 0xc2, 0xcb, 0xd0, 0xd9, 0xae, 0xa7, 0xbc, 0xb5, 0x8a, 0x83, 0x98, 0x91, 
        0x4d, 0x44, 0x5f, 0x56, 0x69, 0x60, 0x7b, 0x72, 0x05, 0x0c, 0x17, 0x1e, 0x21, 0x28, 0x33, 0x3a, 
        0xdd, 0xd4, 0xcf, 0xc6, 0xf9, 0xf0, 0xeb, 0xe2, 0x95, 0x9c, 0x87, 0x8e, 0xb1, 0xb8, 0xa3, 0xaa, 
        0xec, 0xe5, 0xfe, 0xf7, 0xc8, 0xc1, 0xda, 0xd3, 0xa4, 0xad, 0xb6, 0xbf, 0x80, 0x89, 0x92, 0x9b, 
        0x7c, 0x75, 0x6e, 0x67, 0x58, 0x51, 0x4a, 0x43, 0x34, 0x3d, 0x26, 0x2f, 0x10, 0x19, 0x02, 0x0b, 
        0xd7, 0xde, 0xc5, 0xcc, 0xf3, 0xfa, 0xe1, 0xe8, 0x9f, 0x96, 0x8d, 0x84, 0xbb, 0xb2, 0xa9, 0xa0, 
        0x47, 0x4e, 0x55, 0x5c, 0x63, 0x6a, 0x71, 0x78, 0x0f, 0x06, 0x1d, 0x14, 0x2b, 0x22, 0x39, 0x30, 
        0x9a, 0x93, 0x88, 0x81, 0xbe, 0xb7, 0xac, 0xa5, 0xd2, 0xdb, 0xc0, 0xc9, 0xf6, 0xff, 0xe4, 0xed, 
        0x0a, 0x03, 0x18, 0x11, 0x2e, 0x27, 0x3c, 0x35, 0x42, 0x4b, 0x50, 0x59, 0x66, 0x6f, 0x74, 0x7d, 
        0xa1, 0xa8, 0xb3, 0xba, 0x85, 0x8c, 0x97, 0x9e, 0xe9, 0xe0, 0xfb, 0xf2, 0xcd, 0xc4, 0xdf, 0xd6, 
        0x31, 0x38, 0x23, 0x2a, 0x15, 0x1c, 0x07, 0x0e, 0x79, 0x70, 0x6b, 0x62, 0x5d, 0x54, 0x4f, 0x46
    };
    return table[c];
}

uchar
T11(uchar c) {
    static uchar table[256] = {
        0x00, 0x0b, 0x16, 0x1d, 0x2c, 0x27, 0x3a, 0x31, 0x58, 0x53, 0x4e, 0x45, 0x74, 0x7f, 0x62, 0x69, 
        0xb0, 0xbb, 0xa6, 0xad, 0x9c, 0x97, 0x8a, 0x81, 0xe8, 0xe3, 0xfe, 0xf5, 0xc4, 0xcf, 0xd2, 0xd9, 
        0x7b, 0x70, 0x6d, 0x66, 0x57, 0x5c, 0x41, 0x4a, 0x23, 0x28, 0x35, 0x3e, 0x0f, 0x04, 0x19, 0x12, 
        0xcb, 0xc0, 0xdd, 0xd6, 0xe7, 0xec, 0xf1, 0xfa, 0x93, 0x98, 0x85, 0x8e, 0xbf, 0xb4, 0xa9, 0xa2, 
        0xf6, 0xfd, 0xe0, 0xeb, 0xda, 0xd1, 0xcc, 0xc7, 0xae, 0xa5, 0xb8, 0xb3, 0x82, 0x89, 0x94, 0x9f, 
        0x46, 0x4d, 0x50, 0x5b, 0x6a, 0x61, 0x7c, 0x77, 0x1e, 0x15, 0x08, 0x03, 0x32, 0x39, 0x24, 0x2f, 
        0x8d, 0x86, 0x9b, 0x90, 0xa1, 0xaa, 0xb7, 0xbc, 0xd5, 0xde, 0xc3, 0xc8, 0xf9, 0xf2, 0xef, 0xe4, 
        0x3d, 0x36, 0x2b, 0x20, 0x11, 0x1a, 0x07, 0x0c, 0x65, 0x6e, 0x73, 0x78, 0x49, 0x42, 0x5f, 0x54, 
        0xf7, 0xfc, 0xe1, 0xea, 0xdb, 0xd0, 0xcd, 0xc6, 0xaf, 0xa4, 0xb9, 0xb2, 0x83, 0x88, 0x95, 0x9e, 
        0x47, 0x4c, 0x51, 0x5a, 0x6b, 0x60, 0x7d, 0x76, 0x1f, 0x14, 0x09, 0x02, 0x33, 0x38, 0x25, 0x2e, 
        0x8c, 0x87, 0x9a, 0x91, 0xa0, 0xab, 0xb6, 0xbd, 0xd4, 0xdf, 0xc2, 0xc9, 0xf8, 0xf3, 0xee, 0xe5, 
        0x3c, 0x37, 0x2a, 0x21, 0x10, 0x1b, 0x06, 0x0d, 0x64, 0x6f, 0x72, 0x79, 0x48, 0x43, 0x5e, 0x55, 
        0x01, 0x0a, 0x17, 0x1c, 0x2d, 0x26, 0x3b, 0x30, 0x59, 0x52, 0x4f, 0x44, 0x75, 0x7e, 0x63, 0x68, 
        0xb1, 0xba, 0xa7, 0xac, 0x9d, 0x96, 0x8b, 0x80, 0xe9, 0xe2, 0xff, 0xf4, 0xc5, 0xce, 0xd3, 0xd8, 
        0x7a, 0x71, 0x6c, 0x67, 0x56, 0x5d, 0x40, 0x4b, 0x22, 0x29, 0x34, 0x3f, 0x0e, 0x05, 0x18, 0x13, 
        0xca, 0xc1, 0xdc, 0xd7, 0xe6, 0xed, 0xf0, 0xfb, 0x92, 0x99, 0x84, 0x8f, 0xbe, 0xb5, 0xa8, 0xa3
    };
    return table[c];
}

uchar
T13(uchar c) {
    static uchar table[256] = {
        0x00, 0x0d, 0x1a, 0x17, 0x34, 0x39, 0x2e, 0x23, 0x68, 0x65, 0x72, 0x7f, 0x5c, 0x51, 0x46, 0x4b, 
        0xd0, 0xdd, 0xca, 0xc7, 0xe4, 0xe9, 0xfe, 0xf3, 0xb8, 0xb5, 0xa2, 0xaf, 0x8c, 0x81, 0x96, 0x9b, 
        0xbb, 0xb6, 0xa1, 0xac, 0x8f, 0x82, 0x95, 0x98, 0xd3, 0xde, 0xc9, 0xc4, 0xe7, 0xea, 0xfd, 0xf0, 
        0x6b, 0x66, 0x71, 0x7c, 0x5f, 0x52, 0x45, 0x48, 0x03, 0x0e, 0x19, 0x14, 0x37, 0x3a, 0x2d, 0x20, 
        0x6d, 0x60, 0x77, 0x7a, 0x59, 0x54, 0x43, 0x4e, 0x05, 0x08, 0x1f, 0x12, 0x31, 0x3c, 0x2b, 0x26, 
        0xbd, 0xb0, 0xa7, 0xaa, 0x89, 0x84, 0x93, 0x9e, 0xd5, 0xd8, 0xcf, 0xc2, 0xe1, 0xec, 0xfb, 0xf6, 
        0xd6, 0xdb, 0xcc, 0xc1, 0xe2, 0xef, 0xf8, 0xf5, 0xbe, 0xb3, 0xa4, 0xa9, 0x8a, 0x87, 0x90, 0x9d, 
        0x06, 0x0b, 0x1c, 0x11, 0x32, 0x3f, 0x28, 0x25, 0x6e, 0x63, 0x74, 0x79, 0x5a, 0x57, 0x40, 0x4d, 
        0xda, 0xd7, 0xc0, 0xcd, 0xee, 0xe3, 0xf4, 0xf9, 0xb2, 0xbf, 0xa8, 0xa5, 0x86, 0x8b, 0x9c, 0x91, 
        0x0a, 0x07, 0x10, 0x1d, 0x3e, 0x33, 0x24, 0x29, 0x62, 0x6f, 0x78, 0x75, 0x56, 0x5b, 0x4c, 0x41, 
        0x61, 0x6c, 0x7b, 0x76, 0x55, 0x58, 0x4f, 0x42, 0x09, 0x04, 0x13, 0x1e, 0x3d, 0x30, 0x27, 0x2a, 
        0xb1, 0xbc, 0xab, 0xa6, 0x85, 0x88, 0x9f, 0x92, 0xd9, 0xd4, 0xc3, 0xce, 0xed, 0xe0, 0xf7, 0xfa, 
        0xb7, 0xba, 0xad, 0xa0, 0x83, 0x8e, 0x99, 0x94, 0xdf, 0xd2, 0xc5, 0xc8, 0xeb, 0xe6, 0xf1, 0xfc, 
        0x67, 0x6a, 0x7d, 0x70, 0x53, 0x5e, 0x49, 0x44, 0x0f, 0x02, 0x15, 0x18, 0x3b, 0x36, 0x21, 0x2c, 
        0x0c, 0x01, 0x16, 0x1b, 0x38, 0x35, 0x22, 0x2f, 0x64, 0x69, 0x7e, 0x73, 0x50, 0x5d, 0x4a, 0x47, 
        0xdc, 0xd1, 0xc6, 0xcb, 0xe8, 0xe5, 0xf2, 0xff, 0xb4, 0xb9, 0xae, 0xa3, 0x80, 0x8d, 0x9a, 0x97
    };
    return table[c];
}

uchar
T14(uchar c) {
    static uchar table[256] = {
        0x00, 0x0e, 0x1c, 0x12, 0x38, 0x36, 0x24, 0x2a, 0x70, 0x7e, 0x6c, 0x62, 0x48, 0x46, 0x54, 0x5a, 
        0xe0, 0xee, 0xfc, 0xf2, 0xd8, 0xd6, 0xc4, 0xca, 0x90, 0x9e, 0x8c, 0x82, 0xa8, 0xa6, 0xb4, 0xba, 
        0xdb, 0xd5, 0xc7, 0xc9, 0xe3, 0xed, 0xff, 0xf1, 0xab, 0xa5, 0xb7, 0xb9, 0x93, 0x9d, 0x8f, 0x81, 
        0x3b, 0x35, 0x27, 0x29, 0x03, 0x0d, 0x1f, 0x11, 0x4b, 0x45, 0x57, 0x59, 0x73, 0x7d, 0x6f, 0x61, 
        0xad, 0xa3, 0xb1, 0xbf, 0x95, 0x9b, 0x89, 0x87, 0xdd, 0xd3, 0xc1, 0xcf, 0xe5, 0xeb, 0xf9, 0xf7, 
        0x4d, 0x43, 0x51, 0x5f, 0x75, 0x7b, 0x69, 0x67, 0x3d, 0x33, 0x21, 0x2f, 0x05, 0x0b, 0x19, 0x17, 
        0x76, 0x78, 0x6a, 0x64, 0x4e, 0x40, 0x52, 0x5c, 0x06, 0x08, 0x1a, 0x14, 0x3e, 0x30, 0x22, 0x2c, 
        0x96, 0x98, 0x8a, 0x84, 0xae, 0xa0, 0xb2, 0xbc, 0xe6, 0xe8, 0xfa, 0xf4, 0xde, 0xd0, 0xc2, 0xcc, 
        0x41, 0x4f, 0x5d, 0x53, 0x79, 0x77, 0x65, 0x6b, 0x31, 0x3f, 0x2d, 0x23, 0x09, 0x07, 0x15, 0x1b, 
        0xa1, 0xaf, 0xbd, 0xb3, 0x99, 0x97, 0x85, 0x8b, 0xd1, 0xdf, 0xcd, 0xc3, 0xe9, 0xe7, 0xf5, 0xfb, 
        0x9a, 0x94, 0x86, 0x88, 0xa2, 0xac, 0xbe, 0xb0, 0xea, 0xe4, 0xf6, 0xf8, 0xd2, 0xdc, 0xce, 0xc0, 
        0x7a, 0x74, 0x66, 0x68, 0x42, 0x4c, 0x5e, 0x50, 0x0a, 0x04, 0x16, 0x18, 0x32, 0x3c, 0x2e, 0x20, 
        0xec, 0xe2, 0xf0, 0xfe, 0xd4, 0xda, 0xc8, 0xc6, 0x9c, 0x92, 0x80, 0x8e, 0xa4, 0xaa, 0xb8, 0xb6, 
        0x0c, 0x02, 0x10, 0x1e, 0x34, 0x3a, 0x28, 0x26, 0x7c, 0x72, 0x60, 0x6e, 0x44, 0x4a, 0x58, 0x56, 
        0x37, 0x39, 0x2b, 0x25, 0x0f, 0x01, 0x13, 0x1d, 0x47, 0x49, 0x5b, 0x55, 0x7f, 0x71, 0x63, 0x6d, 
        0xd7, 0xd9, 0xcb, 0xc5, 0xef, 0xe1, 0xf3, 0xfd, 0xa7, 0xa9, 0xbb, 0xb5, 0x9f, 0x91, 0x83, 0x8d
    };
    return table[c];
}

void
mixColumns(uchar state[4][4], uchar mode) {
    for (int i = 0; i < 4; i++) {
        uchar col[4];

        for (int j = 0; j < 4; j++) {
            col[j] = state[j][i];
        }

        if (mode == ENCRYPT) {
            mixColumn(col);
        } else {
            invMixColumn(col);
        }

        for (int j = 0; j < 4; j++) {
            state[j][i] = col[j];
        }
    }
}

void
mixColumn(uchar a[4]) {
    uchar b[4];

    b[0] = T2(a[0]) ^ T3(a[1])  ^    a[2]  ^    a[3];
    b[1] =    a[0]  ^ T2(a[1])  ^ T3(a[2]) ^    a[3];
    b[2] =    a[0]  ^    a[1]   ^ T2(a[2]) ^ T3(a[3]);
    b[3] = T3(a[0]) ^    a[1]   ^    a[2]  ^ T2(a[3]);

    for (int i = 0; i < 4; i++) {
        a[i] = b[i];
    }
}

void
invMixColumn(uchar b[4]) {
    uchar a[4];

    a[0] = T14(b[0]) ^ T11(b[1]) ^ T13(b[2]) ^ T9 (b[3]);
    a[1] = T9 (b[0]) ^ T14(b[1]) ^ T11(b[2]) ^ T13(b[3]);
    a[2] = T13(b[0]) ^ T9 (b[1]) ^ T14(b[2]) ^ T11(b[3]);
    a[3] = T11(b[0]) ^ T13(b[1]) ^ T9 (b[2]) ^ T14(b[3]);

    for (int i = 0; i < 4; i++) {
        b[i] = a[i];
    }
}

/*
 *   c[0,1,2,3] => c[1,2,3,0]
 */
void
rotateLeft(uchar c[4]) {
    uchar t = c[0];
    c[0] = c[1];
    c[1] = c[2];
    c[2] = c[3];
    c[3] = t;
}

/*
 *   c[0,1,2,3] => c[3,0,1,2]
 */
void
rotateRight(uchar c[4]) {
    uchar t = c[3];
    c[3] = c[2];
    c[2] = c[1];
    c[1] = c[0];
    c[0] = t;
}

void
keycore(uchar input[4], int i) {
    rotateLeft(input);
    for (int j = 0; j < 4; j++) {
        input[j] = sbox(input[j]);
    }
    input[0] ^= rcon(i);
}

void
keyExpansion(int bits, int b, uchar ekey[], const uchar *passkey) {
    int n     = bits / 8;  // 16, 24, 32
    int bytes = n;
    int rconi = 1;

    // initialize expanded key to encryption key
    for (int i = 0; i < bytes; i++) {
        ekey[i] = passkey[i];
    }

    // until there are "b" bytes of expanded key 
    while (bytes < b) {
        uchar t[4];

        // previous 4 bytes of expanded key
        for (int i = 0; i < 4; i++) {
            t[i] = ekey[bytes - 4 + i]; // previous 4 bytes of expanded key
        }

        // key schedule core with rcon(i)
        keycore(t, rconi++);

        // 4 times for the next 16 bytes of expanded key
        for (int iter = 0; iter < 4; iter++) {
            for (int i = 0; i < 4; i++) {
                t[i] ^= ekey[bytes - n + i];
                ekey[bytes + i] = t[i];
            }
            bytes += 4;
        }

        // 128 bit processing is complete
        // 192 requires 8 more bytes
        // 256 requires 16 more bytes + another sbox()
        if (bits == 192 && bytes < b) {
            for (int iter = 0; iter < 2; iter++) {
                for (int i = 0; i < 4; i++) {
                    t[i] ^= ekey[bytes - n + i];
                    ekey[bytes + i] = t[i];
                }
                bytes += 4;
            }
        } else if (bits == 256 && bytes < b) {
            for (int i = 0; i < 4; i++) {
                t[i] = sbox(t[i]) ^ ekey[bytes - n + i];
                ekey[bytes + i] = t[i];
            }
            bytes += 4;

            for (int iter = 0; iter < 3; iter++) {
                for (int i = 0; i < 4; i++) {
                    t[i] ^= ekey[bytes - n + i];
                    ekey[bytes + i] = t[i];
                }
                bytes += 4;
            }
        }
    }
}

void
addRoundKey(uchar state[4][4], uchar ekey[], int round, int cycles, uchar mode) {
    int offset = (mode == ENCRYPT) ? 16*round : 16*(cycles - round);
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[j][i] ^= ekey[offset++]; // index state as column major
        }
    }
}

void
subBytes(uchar state[4][4], uchar mode) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = (mode == ENCRYPT) ? sbox(state[i][j]) : invSbox(state[i][j]);
        }
    }
}

/*
 *                             mode == Encrypt
 *              Input                               Output
 * a[0][0] a[0][1] a[0][2] a[0][3]  =>  a[0][0] a[0][1] a[0][2] a[0][3]
 * a[1][0] a[1][1] a[1][2] a[1][3]  =>  a[1][1] a[1][2] a[1][3] a[1][0]
 * a[2][0] a[2][1] a[2][2] a[2][3]  =>  a[2][2] a[2][3] a[2][0] a[2][1]
 * a[3][0] a[3][1] a[3][2] a[3][3]  =>  a[3][3] a[3][0] a[3][1] a[3][2]
 */
void
shiftRows(uchar state[4][4], uchar mode) {
    if (mode == ENCRYPT) {
        rotateLeft(state[1]);
        rotateLeft(state[2]); rotateLeft(state[2]);
        rotateRight(state[3]);
    } else {
        rotateRight(state[1]);
        rotateRight(state[2]); rotateRight(state[2]);
        rotateLeft(state[3]);
    }
}

/*
 *     Round  Operation for bits == 128
 *     -      addRoundKey(state)
 *     0      addRoundKey(mixColumns(shiftRows(subBytes(state))))
 *     1      addRoundKey(mixColumns(shiftRows(subBytes(state))))
 *     2      addRoundKey(mixColumns(shiftRows(subBytes(state))))
 *     3      addRoundKey(mixColumns(shiftRows(subBytes(state))))
 *     4      addRoundKey(mixColumns(shiftRows(subBytes(state))))
 *     5      addRoundKey(mixColumns(shiftRows(subBytes(state))))
 *     6      addRoundKey(mixColumns(shiftRows(subBytes(state))))
 *     7      addRoundKey(mixColumns(shiftRows(subBytes(state))))
 *     8      addRoundKey(mixColumns(shiftRows(subBytes(state))))
 *     9      addRoundKey(shiftRows(subBytes(state)))
 */
void
aesEncrypt(int bits, int esize, const uchar *passkey, const uchar *data, int nbytes, int mode, const uchar *iv, uchar *output) {
    uchar state[4][4] = { {0,0,0,0},{0,0,0,0},{0,0,0,0},{0,0,0,0} };
    uchar ekey[esize]; // esize is one of (176, 208, or 240)
    uchar cipherText[16];
    uchar pad = (nbytes % 16) ? 0 : 16;
    int o = 0;
    int cycles = (bits == 128) ? 10 : (bits == 192) ? 12 : 14;

    /*
     * dwf -- padding implementation notes: Wed Mar  1 22:19:23 MST 2017
     *
     * Computing PKCS#7 padding
     *   High Level:
     *      If all the "data" bytes have been consumed when loading the "state" then
     *      determine the pad value needed to fill the remainder of "state" based on
     *      how much more data is needed to fill the block.
     *      
     *      Set "pad" value once to the computed value:
     *
     *          if (!pad) pad = 16 - n % 16; // PKCS#7 padding
     *      
     *   Exception:
     *      The above doesn't work when nbytes is an even block size and a full block of
     *      padded (16) is needed.  An additional full loop iteration is needed with
     *      no data bytes to consume.
     *
     *      To handle this we initialize "pad" to 0 or 16 and modify the loop condition to:
     *
     *          ( n < nbytes + pad/16 )
     *
     *      only when ( nbytes % 16 == 0 ) will one iteration be added:
     *
     *          + ( pad / 16 )  // evaluates to 0 or 1
     *
     *      The "pad" value has already been set (to 16) so it wont be re-computed, resulting
     *      in an extra full block fill of 16 (hex: 10)
     */

    if (mode == CBC) {
        for (int i = 0; i < 16; i++) {
            cipherText[i] = (iv) ? iv[i] : 0;
        }
    }

    keyExpansion(bits, esize, ekey, passkey);

    for (int n = 0; n < nbytes + pad/16;) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                if (n < nbytes) {
                    state[j][i] = data[n];
                } else {
                    if (!pad) pad = 16 - n % 16; // PKCS#7 padding
                    state[j][i] = pad;
                }

                if (mode == CBC) {
                    state[j][i] ^= cipherText[j + 4*i];
                }
                n++;
            }
        }

        addRoundKey(state, ekey, 0, cycles, ENCRYPT);

        for (int i = 1; i <= cycles; i++) {
            subBytes(state, ENCRYPT);
            shiftRows(state, ENCRYPT);
            if (i < cycles) {
                mixColumns(state, ENCRYPT);
            }
            addRoundKey(state, ekey, i, cycles, ENCRYPT);
        }

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                output[o++] = cipherText[j + 4*i] = state[j][i];
            }
        }
    }
}

void
aesEncryptCTR(int bits, int esize, const uchar *passkey, const uchar *data, int nbytes, const uchar *iv, uchar *output) {
    unsigned long counter = 0;
    unsigned long be = 0;
    int n = 0;
    uchar ctrBlock[16];
    uchar outBlocks[32];

    if (iv) {
        memcpy(ctrBlock, iv, 8);
        memcpy(&be, iv + 8, 8);
        be = ntohll(be);
        memcpy(&counter, &be, 8);
    } else {
        memset(ctrBlock, 0, 8);
    }

    while (n < nbytes) {
        be = ntohll(counter);
        memcpy(ctrBlock + 8, &be, 8);
        aesEncrypt(bits, esize, passkey, ctrBlock, 16, ECB, iv, outBlocks);
        for (int i = 0; n < nbytes && i < 16; i++, n++) {
            output[n] = data[n] ^ outBlocks[i];
        }
        counter++;
    }
}

/*
 * Reverse order of encrypt in addition to the inverse of each function
 *
 *     Round  Operation for bits == 128
 *     -      addRoundKey(state)
 *     0      mixColumns(addRoundKey(subBytes(shiftRows(state))))
 *     1      mixColumns(addRoundKey(subBytes(shiftRows(state))))
 *     2      mixColumns(addRoundKey(subBytes(shiftRows(state))))
 *     3      mixColumns(addRoundKey(subBytes(shiftRows(state))))
 *     4      mixColumns(addRoundKey(subBytes(shiftRows(state))))
 *     5      mixColumns(addRoundKey(subBytes(shiftRows(state))))
 *     6      mixColumns(addRoundKey(subBytes(shiftRows(state))))
 *     7      mixColumns(addRoundKey(subBytes(shiftRows(state))))
 *     8      mixColumns(addRoundKey(subBytes(shiftRows(state))))
 *     9      addRoundKey(subBytes(shiftRows(state)))
 */
void
aesDecrypt(int bits, int esize, const uchar *passkey, const uchar *data, int nbytes, int mode, const uchar *iv, uchar *output) {
    uchar state[4][4] = { {0,0,0,0},{0,0,0,0},{0,0,0,0},{0,0,0,0} };
    uchar ekey[esize]; // esize is one of (176, 208, or 240)
    uchar cipherText[16];
    int o = 0;
    int cycles = (bits == 128) ? 10 : (bits == 192) ? 12 : 14;

    if (mode == CBC) {
        for (int i = 0; i < 16; i++) {
            cipherText[i] = (iv) ? iv[i] : 0;
        }
    }

    keyExpansion(bits, esize, ekey, passkey);

    for (int n = 0; n < nbytes; n += 16) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[j][i] = data[n + j + 4*i];
            }
        }

        addRoundKey(state, ekey, 0, cycles, DECRYPT);

        for (int i = 1; i <= cycles; i++) {
            shiftRows(state, DECRYPT);
            subBytes(state, DECRYPT);
            addRoundKey(state, ekey, i, cycles, DECRYPT);
            if (i < cycles) {
                mixColumns(state, DECRYPT);
            }
        }

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                if (mode == CBC) {
                    int offset = j + 4*i;
                    state[j][i] ^= cipherText[offset];
                    cipherText[offset] = data[n + offset];
                }
                output[o++] = state[j][i];
            }
        }
    }
}
