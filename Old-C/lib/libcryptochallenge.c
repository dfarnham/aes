#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>

#include "libcryptochallenge.h"

void    panic                   (int, const char *, ...);
void    b64Encode               (const uchar[3], uchar[4], size_t);
int     b64Decode               (const uchar[4], uchar[3]);
int     hammingDistance         (const uchar *, const uchar *);
int     hexCharVal              (const char);
int     hexByteVal              (const char *);
void    hexBytes                (uchar *, const char *);
void    hexnBytes               (uchar *, const char *, int);
int     nullPKCS7               (uchar *);
int     hexDecodeFromFilePtr    (FILE *, uchar **);
int     b64DecodeFromBuffer     (const uchar *, size_t, uchar **);
int     b64DecodeFromFilePtr    (FILE *, uchar **);
int     readFromFilePtr         (FILE *, uchar **);
double  runningMean             (int, double, double);
void    randomBytes16           (uchar [16], int);
int     BLOCKS                  (int);
int     PAD_BLOCKS              (int);


void
panic(int level, const char *fmt, ...) {
    va_list vptr;

    switch (level) {
        case WARN:
            fprintf (stderr, "Warning: ");
            break;
        case FATAL:
            fprintf (stderr, "Error: ");
            break;
        default:
            fprintf (stderr, "Unknown: ");
    }

    va_start(vptr, fmt);
    vfprintf (stderr, fmt, vptr);
    va_end(vptr);

    if (level == FATAL) {
        exit(1);
    }
}

/*******************************************************************************
 * b64Encode:
 *   Examples: https://en.wikipedia.org/wiki/Base64
 *
 *    Length  Input                 Length  Output                        Padding
 *    ------  --------------------  ------  ----------------------------  -------
 *      20    any carnal pleasure.    28    YW55IGNhcm5hbCBwbGVhc3VyZS4=    1
 *      19    any carnal pleasure     28    YW55IGNhcm5hbCBwbGVhc3VyZQ==    2
 *      18    any carnal pleasur      24    YW55IGNhcm5hbCBwbGVhc3Vy        0
 *      17    any carnal pleasu       24    YW55IGNhcm5hbCBwbGVhc3U=        1
 *      16    any carnal pleas        24    YW55IGNhcm5hbCBwbGVhcw==        2
 *******************************************************************************/
void
b64Encode(const uchar src[3], uchar dst[4], size_t n) {
    if (!n) return;

    B64 b64 = { {0, 0, 0} };  // zero fill
    static const char *b64table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    for (int j=0; j < n; j++) {
        b64.bytes[2-j] = src[j]; // fill "n" B64 bytes in reverse order (n in range [1,3])
    }

    dst[0] = b64table[b64.u.a];
    dst[1] = b64table[b64.u.b];

    if (n == 3) {
        dst[2] = b64table[b64.u.c];
        dst[3] = b64table[b64.u.d];
    } else if (n == 2) {
        dst[2] = b64table[b64.u.c];
        dst[3] = '=';  // pad
    } else if (n == 1) {
        dst[2] = dst[3] = '='; // pad
    }
}

int
b64Decode(const uchar src[4], uchar dst[3]) {
    int n;

    B64 b64 = { {0, 0, 0} };  // zero fill
    //static const char *b64table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static const char rb64table[] = { 62,                                                 //  "+"
                                      0 , 0 , 0 ,                                         // unused
                                      63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,         //  "/" .. "9"
                                      0 , 0 , 0 , 0 , 0 , 0 , 0 ,                         // unused
                                      0 , 1 , 2 , 3 , 4 , 5 , 6 , 7 , 8 , 9 , 10, 11, 12, // "A" - "M"
                                      13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, // "N" - "Z"
                                      0 , 0 , 0 , 0 , 0 , 0 ,                             // unused
                                      26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, // "a" - "m"
                                      39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, // "n" - "z"
                                    };

    b64.u.a = rb64table[src[0] - '+']; // strchr(b64table, src[0]) - b64table;
    b64.u.b = rb64table[src[1] - '+']; // strchr(b64table, src[1]) - b64table;
    dst[0] = b64.bytes[2];

    if (src[3] == '=') {
        if (src[2] == '=') {
            n = 1;
        } else {
            b64.u.c = rb64table[src[2] - '+']; // strchr(b64table, src[2]) - b64table;
            dst[1] = b64.bytes[1];
            n = 2;
        }
    } else {
        b64.u.c = rb64table[src[2] - '+']; // strchr(b64table, src[2]) - b64table;
        b64.u.d = rb64table[src[3] - '+']; // strchr(b64table, src[3]) - b64table;
        dst[1] = b64.bytes[1];
        dst[2] = b64.bytes[0];
        n = 3;
    }

    return n;
}

/**************************************************
 * b64DecodeFromBuffer:
 *   Base64 decode a "src" buffer to a "dst" buffer
 *   The "dst" buffer memory is allocated and the caller
 *   is responsible for free()'ing
 *   Returns the number of bytes decoded
 **************************************************/
int
b64DecodeFromBuffer(const uchar *src, size_t n, uchar **dst) {
    uchar b64d[3], b64e[4];
    int dataSize = BUFSIZ;
    int nbytes = 0;
    int c = 0;
    int valid;

    // allocate an initial size of BUFSIZ, that will be resized if needed
    dataSize = BUFSIZ;
    if (!(*dst = (uchar *)malloc(dataSize * sizeof(uchar)))) {
        panic(FATAL, "b64DecodeFromBuffer() failed malloc()\n");
    }

    // Base64 decode the "src" to the "dst" buffer
    while (c + 4 <= n) {
        memcpy(b64e, src + c, 4);
        c += 4;
        valid = 0;

        // skip any embedded newlines in formatted Base64
        while (!valid) {
            valid = 1;
            for (int i = 0; i < 4; i++) {
                if (b64e[i] == '\n' || b64e[i] == '\r') {
                    valid = 0;
                    for (int j = i; j < 3; j++) {
                        b64e[j] = b64e[j+1];
                    }
                    if (c + 1 == n) {
                        panic(FATAL, "\n** b64decodeFromBuffer() Unexpected EOF **\n");
                    }
                    b64e[3] = src[c++];
                }
            }
        }

        // resize if a full block (3 bytes) exceeds dataSize
        if (nbytes + 3 > dataSize) {
            dataSize += BUFSIZ;
            if (!(*dst = (uchar *)realloc(*dst, dataSize * sizeof(uchar)))) {
                panic(FATAL, "b64decodeFromBuffer() failed realloc()\n");
            }
        }

        switch (b64Decode(b64e, b64d)) {
            case 1:
                (*dst)[nbytes++] = b64d[0];
                break;
            case 2:
                (*dst)[nbytes++] = b64d[0];
                (*dst)[nbytes++] = b64d[1];
                break;
            case 3:
                (*dst)[nbytes++] = b64d[0];
                (*dst)[nbytes++] = b64d[1];
                (*dst)[nbytes++] = b64d[2];
                break;
            default:
                panic(FATAL, "b64DecodeFromBuffer() Yikes, not possible\n");
        }
    }

    return nbytes; // number of bytes decoded
}

/**************************************************
 * b64DecodeFromFilePtr:
 *   Base64 decode a file to a buffer
 *   The buffer memory is allocated and the caller
 *   is responsible for free()'ing
 *   Returns the number of bytes decoded
 **************************************************/
int
b64DecodeFromFilePtr(FILE *fp, uchar **data) {
    uchar *fileBytes;
    int nFileBytes, nDataBytes;

    nFileBytes = readFromFilePtr(fp, &fileBytes);
    nDataBytes = b64DecodeFromBuffer(fileBytes, nFileBytes, data);
    free(fileBytes);
    return nDataBytes; // number of bytes decoded
}

/**************************************************
 * hexDecodeFromFilePtr:
 *   hex decode from a FILE * into a buffer
 *   The buffer memory is allocated and the caller
 *   is responsible for free()'ing
 *   Returns the number of bytes decoded
 **************************************************/
int
hexDecodeFromFilePtr(FILE *fp, uchar **data) {
    uchar *fileBytes;
    int nFileBytes, nDataBytes;

    nFileBytes = readFromFilePtr(fp, &fileBytes);
    if (nFileBytes % 2) {
        panic(FATAL, "hexDecodeFromFilePtr() invalid conversion length %d\n", nFileBytes);
    }

    nDataBytes = nFileBytes / 2;
    if (!(*data = (uchar *)calloc(nDataBytes, sizeof(uchar)))) {
        panic(FATAL, "hexDecodeFromFilePtr() failed calloc()\n");
    }

    hexnBytes(*data, (char *)fileBytes, nFileBytes);
    free(fileBytes);
    return nDataBytes; // number of bytes decoded
}

/**************************************************
 * readFromFilePtr:
 *   Read contents from a FILE * into a buffer
 *   The buffer memory is allocated and the caller
 *   is responsible for free()'ing
 *   Returns the number of bytes read
 **************************************************/
int
readFromFilePtr(FILE *fp, uchar **data) {
    int n, dataSize = BUFSIZ, nbytes = 0;

    // allocate an initial size of BUFSIZ, that will be resized if needed
    if (!(*data = (uchar *)malloc(dataSize * sizeof(uchar)))) {
        panic(FATAL, "readFromFilePtr() failed malloc()\n");
    }

    // Base64 decode the input to the "data" buffer
    while ((n = fread(*data + nbytes, sizeof(uchar), BUFSIZ, fp)) == BUFSIZ) {
        nbytes += n;
        dataSize += BUFSIZ;
        if (!(*data = (uchar *)realloc(*data, dataSize * sizeof(uchar)))) {
            panic(FATAL, "readFromFilePtr() failed realloc()\n");
        }
    }

    return nbytes + n;
}

int
hexCharVal(const char c) {
    return (c >= '0' && c <= '9') ? c - '0'
                                  : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                                                           : c - 'A' + 10;
}

int
hexByteVal(const char *h) {
    // char hex[3] = { *h, *(h+1), 0 };
    // return strtol(hex, (char **)NULL, 16);
    return 16 * hexCharVal(*h) + hexCharVal(*(h+1));
}

/**************************************************
 * hexBytes:
 *   treat src characters as 2 byte hex and convert
 *   to bytes stored in dst
 *
 * src    - null terminated hex string
 * dst    - destination buffer
 * len    - length of src to convert
 *
 * Example: strlen(src) == 32
 *          src    = "50617420547261766572732042616e64"
 *          dst    = "Pat Travers Band"
 **************************************************/
void
hexnBytes(uchar *dst, const char *src, int len) {
    if (len % 2) {
        panic(FATAL, "hexnBytes(): invalid conversion length %d\n", len);
    }
    for (int i = 0; i < len && src[i] && src[i+1]; i += 2) {
        if (isxdigit(src[i]) && isxdigit(src[i+1])) {
            *dst++ = hexByteVal(src + i);
        } else {
            panic(FATAL, "hexBytes(): invalid conversion at: %c%c\n", src[i], src[i+1]);
        }
    }
}

void
hexBytes(uchar *dst, const char *src) {
    hexnBytes(dst, src, strlen(src));
}

/**************************************************
 * nullPKCS7:
 * block  - input block of BLKSZ
 *   replaces PKCS#7 padding in a block with NULL's
 *
 *   returns the number of bytes modified (pad value)
 *   or 0 if the padding is not valid PKCS#7
 *
 * NOTE: an invalid input block may still be modified!
 **************************************************/
int
nullPKCS7(uchar *block) {
    int pad = block[BLKSZ - 1];

    if (pad == 0 || pad > 16) {
        return 0;
    }

    for (int i = 0; i < pad; i++) {
        if (block[BLKSZ - 1 - i] != pad) {
            return 0;
        }
        block[BLKSZ - 1 - i] = '\0';
    }

    return pad;
}


/**************************************************
 * hammingDistance:
 *   Returns the number of bit differnces
 *   between two null-terminated input strings
 **************************************************/
int
hammingDistance(const uchar *s1, const uchar *s2) {
    // lookup table for the number of "1" bits for the range 0-15 (0x0-0xf)
    static char nibbleOnBits[] = { 0, /* 0000 */
                                   1, /* 0001 */
                                   1, /* 0010 */
                                   2, /* 0011 */
                                   1, /* 0100 */
                                   2, /* 0101 */
                                   2, /* 0110 */
                                   3, /* 0111 */
                                   1, /* 1000 */
                                   2, /* 1001 */
                                   2, /* 1010 */
                                   3, /* 1011 */
                                   2, /* 1100 */
                                   3, /* 1101 */
                                   3, /* 1110 */
                                   4, /* 1111 */ };
    int bitCount = 0;
    while (*s1 && *s2) {
        uchar uc = *s1++ ^ *s2++;
        bitCount += nibbleOnBits[uc & 0x0f] + nibbleOnBits[uc >> 4];
    }
    return bitCount;
}


/**************************************************
 * runningMean:
 *   Returns the new mean after adding "value"
 *   mean = old_mean * ((n - 1) / n) + (v / n)
 **************************************************/
double
runningMean(int n, double currentMean, double value) {
    return (n <= 1) ? value
                    : currentMean * ((n - 1) / (double)n) + (value / n);
}


/**************************************************
 * randomBytes16:
 *   Generate a random 16 bytes
 *   mode:
 *     0  byte values in range 32-126
 *     1  byte values in range 0-255
 **************************************************/
void
randomBytes16(uchar buffer[16], int mode) {
    if (mode) {
        arc4random_buf(buffer, 16);
    } else {
        for (int i = 0; i < 16; i++) {
            do {
                buffer[i] = arc4random_uniform(127);
            } while (buffer[i] < 32);
        }
    }
}

int
BLOCKS(int n) {
    return n / BLKSZ + (n % BLKSZ > 0);
}

int
PAD_BLOCKS(int n) {
    return n / BLKSZ + 1;
}
