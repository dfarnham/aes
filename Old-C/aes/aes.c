#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>

#include "libcryptochallenge.h"

/********************************************
 *
 * https://cryptopals.com/sets/1/challenges/7
 *
 ********************************************/

/*
 * Extern functions
 */
extern void     panic                   (int, const char *, ...);
extern int      hexDecodeFromFilePtr    (FILE *, uchar **);
extern int      b64DecodeFromFilePtr    (FILE *, uchar **);
extern void     b64Encode               (const uchar src[], uchar dst[], size_t);
extern int      readFromFilePtr         (FILE *, uchar **);
extern int      hexBytes                (uchar *, const char *);
extern void     aes128Encrypt           (const uchar *, const uchar *, int, int, const uchar *, uchar *);
extern void     aes192Encrypt           (const uchar *, const uchar *, int, int, const uchar *, uchar *);
extern void     aes256Encrypt           (const uchar *, const uchar *, int, int, const uchar *, uchar *);
extern void     aes128Decrypt           (const uchar *, const uchar *, int, int, const uchar *, uchar *);
extern void     aes192Decrypt           (const uchar *, const uchar *, int, int, const uchar *, uchar *);
extern void     aes256Decrypt           (const uchar *, const uchar *, int, int, const uchar *, uchar *);
extern void     randomBytes16           (uchar[], int);
extern int      BLOCKS                  (int);
extern int      PAD_BLOCKS              (int);

/*
 * Extern test functions
 */
extern int  _test128 ();
extern int  _test192 ();
extern int  _test256 ();


/*
 * Local functions
 */
void    usage   (const char *);
int     main    (int, char **);

/* ---------------------------------------------------------------- */

void
usage(const char *prog) {
    fprintf(stderr, "Usage: %s -[128|192|256] -[ecb|cbc|ctr] -[encrypt|decrypt] -[hex]key passkey\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, " -128, -192, -256    key length\n");
    fprintf(stderr, " -encrypt, -decrypt  encrypt or decrypt\n");
    fprintf(stderr, " -ecb, -cbc, -ctr    block cipher mode, -ecb,-cbc will be PKCS#7 padded\n");
    fprintf(stderr, " -key passkey        16,24,32 byte passkey\n");
    fprintf(stderr, " -hexkey passkey     2-byte hex characters converted to 16,24,32 bytes\n");
    fprintf(stderr, " -iv vector          16 byte initialization vector\n");
    fprintf(stderr, " -hexiv vector       2-byte hex characters converted to 16 bytes\n");
    fprintf(stderr, " -randiv             system generated \"iv\" output as first block on -encrypt\n");
    fprintf(stderr, "                     treat first block as \"iv\" on -decrypt\n");
    fprintf(stderr, " -nopkcs             prevents a \"full\" pad block being output on -encrypt\n");
    fprintf(stderr, "                     skip PKCS#7 pad removal on -decrypt\n");
    fprintf(stderr, " -[i]base64          treat input as Base64 encoded\n");
    fprintf(stderr, " -obase64            output as Base64 encoded\n");
    fprintf(stderr, " -[i]hex             treat input as 2-byte hex\n");
    fprintf(stderr, " -ohex               output as 2-byte hex\n");
    fprintf(stderr, " -file name          file or stdin, filename of - is treated as stdin\n");
    exit(1);
}

int
main(int argc, char **argv) {
    char *progname = argv[0];
    FILE *fp   = stdin;
    char *file = NULL;
    int bits = 0;
    int mode = -1;
    int readBytes   = 0;
    int outputBytes = 0;
    int ivBlock     = 0;
    char *iv = NULL, *hexiv = NULL, *key = NULL, *hexkey = NULL;
    uchar *data = NULL, *output = NULL;
    uchar ivector[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
    uchar passkey[32] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                          0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };

    static int bits128, bits192, bits256;
    static int encrypt, decrypt;
    static int base64, obase64;
    static int hex, ohex;
    static int nopkcs;
    static int test128, test192, test256;
    static int ecb, cbc, ctr;
    static int randiv;
    static struct option longopts[] = {
        { "128"     , no_argument , &bits128 , 128 } ,
        { "192"     , no_argument , &bits192 , 192 } ,
        { "256"     , no_argument , &bits256 , 256 } ,
        { "nopkcs"  , no_argument , &nopkcs  , 1 } ,
        { "base64"  , no_argument , &base64  , 1 } ,
        { "ibase64" , no_argument , &base64  , 1 } ,
        { "obase64" , no_argument , &obase64 , 1 } ,
        { "hex"     , no_argument , &hex     , 1 } ,
        { "ihex"    , no_argument , &hex     , 1 } ,
        { "ohex"    , no_argument , &ohex    , 1 } ,
        { "ecb"     , no_argument , &ecb     , 1 } ,
        { "cbc"     , no_argument , &cbc     , 1 } ,
        { "ctr"     , no_argument , &ctr     , 1 } ,
        { "randiv"  , no_argument , &randiv  , 1 } ,
        { "encrypt" , no_argument , &encrypt , 1 } ,
        { "decrypt" , no_argument , &decrypt , 1 } ,
        { "test128" , no_argument , &test128 , 1 } ,
        { "test192" , no_argument , &test192 , 1 } ,
        { "test256" , no_argument , &test256 , 1 } ,

        { "help"    , no_argument       , NULL , 'z' } ,
        { "file"    , required_argument , NULL , 'f' } ,
        { "key"     , required_argument , NULL , 'k' } ,
        { "hexkey"  , required_argument , NULL , 'x' } ,
        { "iv"      , required_argument , NULL , 'i' } ,
        { "hexiv"   , required_argument , NULL , 'j' } ,
        { NULL      , 0                 , NULL ,  0  }
    };

    int opt;
    while ((opt = getopt_long_only(argc, argv, "zf:k:x:i:j:", longopts, NULL)) != -1) {
        switch (opt) {
            case 0: break;

            case 'i':
                iv     = optarg; break;
            case 'j':
                hexiv  = optarg; break;
            case 'f':
                file   = optarg; break;
            case 'k':
                key    = optarg; break;
            case 'x':
                hexkey = optarg; break;
            case 'z':
            default:
                usage(progname);
        }
    }
    argc -= optind;
    argv += optind;

    /*
     * test for internal options (which trigger an exit)
     */
    if (test128 || test192 || test256) {
        if (test128) _test128();
        if (test192) _test192();
        if (test256) _test256();
        exit(0);
    }

    /* ================================================================ */

    /*
     * argument validation
     */
    if (argc != 0) {
        usage(progname);
    } else if (!(key || hexkey)) {
        fprintf(stderr, "** missing required: --(hex)key=passkey\n\n");
        usage(progname);
    } else if ((ecb && cbc && ctr) || !(ecb || cbc || ctr)) {
        fprintf(stderr, "** missing required: -ecb, -cbc, -ctr)\n\n");
        usage(progname);
    } else if ((encrypt && decrypt) || !(encrypt || decrypt)) {
        fprintf(stderr, "** missing required: -encrypt, -decrypt)\n\n");
        usage(progname);
    } else if ((bits128 && bits192 && bits256) || !(bits128 || bits192 || bits256)) {
        fprintf(stderr, "** missing required: -128, -192, -256)\n\n");
        usage(progname);
    } else if (key) {
        bits = bits128 + bits192 + bits256;
        if (strlen(key) != bits >> 3) {
            fprintf(stderr, "** -%d requires a --key be length(%d)\n\n", bits, bits >> 3 );
            usage(progname);
        }
    } else if (hexkey) {
        bits = bits128 + bits192 + bits256;
        if (strlen(hexkey) != bits >> 2) {
            fprintf(stderr, "** -%d requires a --hexkey be length(%d)\n\n", bits, bits >> 2 );
            usage(progname);
        }
    }

    if (ecb) {
        mode = ECB;
    } else if (cbc) {
        mode = CBC;
    } else if (ctr) {
        mode = CTR;
    }

    if (randiv && encrypt) {
        randomBytes16(ivector, 1);
    } else if (iv) {
        strncpy((char *)ivector, iv, 16);  // '\0' filled if short
    } else if (hexiv) {
        hexBytes(ivector, hexiv);
    }

    // bits/8 == 16,24,32
    if (key) {
        memcpy(passkey, key, bits/8);
    } else if (hexkey) {
        hexBytes(passkey, hexkey);
    }

    if (file) {
        if (!strcmp("-", file)) {
            fp = stdin;
        } else if (!(fp = fopen(file, "r"))) {
            panic(FATAL, "%s can't read file \"%s\"\n", progname, file);
        }
    }

    // read the input and perform conversions before encrypt/decrypt
    if (base64) {
        readBytes = b64DecodeFromFilePtr(fp, &data);
    } else if (hex) {
        readBytes = hexDecodeFromFilePtr(fp, &data);
    } else {
        readBytes = readFromFilePtr(fp, &data);
    }
    fclose(fp);

    // output buffer allocation:
    // size for worst case (iv + padded blocks)
    if (!(output = (uchar *)calloc(16 * PAD_BLOCKS(16 + readBytes), sizeof(uchar)))) {
        panic(FATAL, "failed calloc()\n");
    }

    // iv will reside in the first block when invoked with -randiv for -[cbc|ctr]
    ivBlock = (randiv && (cbc || ctr)) ? 16 : 0;

    if (encrypt) {
        // calculate the number of outputBytes
        if (ctr) {
            outputBytes = readBytes + ivBlock;
        } else if (nopkcs) {
            outputBytes = 16 * BLOCKS(readBytes + ivBlock);  // protect against output of a full pad block
        } else {
            outputBytes = 16 * PAD_BLOCKS(readBytes + ivBlock);
        }

        if (ivBlock) {
            memcpy(output, ivector, 16);
        }

        switch (bits) {
            case 128:
                aes128Encrypt(passkey, data, readBytes, mode, ivector, output + ivBlock);
                break;
            case 192:
                aes192Encrypt(passkey, data, readBytes, mode, ivector, output + ivBlock);
                break;
            case 256:
                aes256Encrypt(passkey, data, readBytes, mode, ivector, output + ivBlock);
                break;
        }
    } else {
        if (ivBlock) {
            memcpy(ivector, data, 16);
        }

        switch (bits) {
            case 128:
                aes128Decrypt(passkey, data + ivBlock, readBytes, mode, ivector, output);
                break;
            case 192:
                aes192Decrypt(passkey, data + ivBlock, readBytes, mode, ivector, output);
                break;
            case 256:
                aes256Decrypt(passkey, data + ivBlock, readBytes, mode, ivector, output);
                break;
        }

        // calculate the number of outputBytes
        if (ctr) {
            outputBytes = readBytes - ivBlock;
        } else if (nopkcs) {
            outputBytes = 16 * BLOCKS(readBytes - ivBlock);
        } else {
            int bytes = 16 * BLOCKS(readBytes - ivBlock);
            outputBytes = bytes - output[bytes - 1];  // PKCS#7 padding removal
        }
    }

    if (obase64) {
        uchar dst[4];
        int n = 0, pretty = 1;
        while (n + 3 < outputBytes) {
            b64Encode(output + n, dst, 3);
            printf("%c%c%c%c", dst[0], dst[1], dst[2], dst[3]);
            if (++pretty % 20 == 0) {
                printf("\n");
                pretty = 1;
            }
            n += 3;
        }
        if (n < outputBytes) {
            b64Encode(output + n, dst, outputBytes - n);
            printf("%c%c%c%c", dst[0], dst[1], dst[2], dst[3]);
        }
        printf("\n");
    } else if (ohex) {
        for (int i = 0; i < outputBytes; i++) {
            printf("%02x", output[i]);
        }
    } else {
        for (int i = 0; i < outputBytes; i++) {
            printf("%c", output[i]);
        }
    }

    free(data);
    free(output);
    exit(0);
}
