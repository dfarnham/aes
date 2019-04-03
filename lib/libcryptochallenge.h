/*
 * Define the error levels
 */
#define WARN  0
#define FATAL 1

#define ENCRYPT 0
#define DECRYPT 1

#define ECB 0
#define CBC 1
#define CTR 2

#define BLKSZ 16

/*
 * Example of Base64 Encoding "ABC" using shifting
 * or a union on a little endian machine
 *
 * mac-mini$ echo -n ABC | base64
 * QUJD
 *
 * --------------------------------------------------------------------------------
 *
 * static const char *b64table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 *
 * Algorithm using shifting:
 *
 * bytes[0] = 'A'
 * bytes[1] = 'B'
 * bytes[2] = 'C'
 *
 * b64table[bytes[0] >> 2]                               //  b64table[16] == 'Q'
 * b64table[((bytes[0] << 4) & 0x30) | (bytes[1] >> 4)]  //  b64table[20] == 'U'
 * b64table[((bytes[1] << 2) & 0x3c) | (bytes[2] >> 6)]  //  b64table[9]  == 'J'
 * b64table[bytes[2] & 0x3f]                             //  b64table[3]  == 'D'
 *
 * --------------------------------------------------------------------------------
 *
 * Union of 24 bits (3 bytes) and four 6-bit ints for Base64 encoding
 *
 *     'A'       'B'       'C'
 *     65        66        67
 *   bytes[2]  bytes[1]  bytes[0]  <===== "ABC" loaded in reverse of shifting technique
 *   --------  --------  --------
 *   01000001  01000010  01000011
 *   ||||||||  ||||||||  ||||||||
 *   ||||||||  ||||||||  ||++++++ u.d == 000011 == b64table[3] == 'D'
 *   ||||||||  ||||++++  ++ u.c == 001001 == b64table[9] == 'J'
 *   ||||||++  ++++ u.b == 010100 == b64table[20] == 'U'
 *   ++++++ u.a == 010000 == b64table[16] == 'Q'
 *
 */

typedef unsigned char uchar;

typedef union {
    uchar bytes[3];
    struct {
        unsigned d:6;
        unsigned c:6;
        unsigned b:6;
        unsigned a:6;
    } u;
} B64;
