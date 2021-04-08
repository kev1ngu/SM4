// Yuwen Gu, 2021 Spring
// Graduation Design @ Jiangsu Normal University

// GM/T 0002-2012 Chinese National Standard
// SM4 Encryption Alogrithm


#include "SM4_main.hpp"
#include <iostream>
#include <cstring>

#define ENCRYPT 0
#define DECRYPT 1

// System Parameter FK[4]
static const unsigned long FK[4]
{
    0xA3B1BAC6,0x56AA3350,0x677D9197,0xB27022DC
};

// Fixed Parameter CK[32]
static const unsigned long CK[32] =
{
    0x00070E15,0x1C232A31,0x383F464D,0x545B6269,
    0x70777E85,0x8C939AA1,0xA8AFB6BD,0xC4CBD2D9,
    0xE0E7EEF5,0xFC030A11,0x181F262D,0x343B4249,
    0x50575E65,0x6C737A81,0x888F969D,0xA4ABB2B9,
    0xC0C7CED5,0xDCE3EAF1,0xF8FF060D,0x141B2229,
    0x30373E45,0x4C535A61,0x686F767D,0x848B9299,
    0xA0A7AEB5,0xBCC3CAD1,0xD8DFE6ED,0xF4FB0209,
    0x10171E25,0x2C333A41,0x484F565D,0x646B7279
};

//16*16 Sbox
static const unsigned char SboxTable[16][16] =
{
    {0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05},
    {0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99},
    {0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62},
    {0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6},
    {0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8},
    {0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35},
    {0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87},
    {0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e},
    {0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1},
    {0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3},
    {0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f},
    {0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51},
    {0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8},
    {0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0},
    {0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84},
    {0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48}
};

static unsigned char sm4Sbox(unsigned char inch)
{
    unsigned char *pTable = (unsigned char *)SboxTable;
    unsigned char retVal = (unsigned char)(pTable[inch]);
    return retVal;
}

//global namespace std
using namespace std;

//Varaible mode controls mode to use.
//Array rk[32] stands for round keys(a.k.a. sub keys).
typedef struct{
    int mode;
    unsigned long rk[32];
} sm4_context;

//swap func define
#define SWAP(a,b) { unsigned long t = a; a = b; b = t; t = 0; }

//bit operations
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
      n = ( (unsigned long) (b)[(i) + 0] << 24 )        \
        | ( (unsigned long) (b)[(i) + 1] << 16 )        \
        | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 3]       );       \
}

#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i) + 0] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}

//expression 8: <<< operator
#define SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))

//expression 8:
static unsigned long linearTransformation(unsigned long ka)
{
    unsigned long bb = 0;
    unsigned long rk = 0;
    unsigned char a[4];
    unsigned char b[4];
    PUT_ULONG_BE(ka,a,0)
    b[0] = sm4Sbox(a[0]);
    b[1] = sm4Sbox(a[1]);
    b[2] = sm4Sbox(a[2]);
    b[3] = sm4Sbox(a[3]);
    GET_ULONG_BE(bb,b,0);
    rk = bb^(ROTL(bb, 13))^(ROTL(bb, 23));
    return rk;
}

static void sm4_keyExpansion( unsigned long rndKey[32], unsigned char key[16] )
{
    unsigned long MK[4];
    unsigned long k[36];

    GET_ULONG_BE( MK[0], key, 0);
    GET_ULONG_BE( MK[1], key, 4);
    GET_ULONG_BE( MK[2], key, 8);
    GET_ULONG_BE( MK[3], key, 12);
    
    k[0] = MK[0]^FK[0];
    k[1] = MK[1]^FK[1];
    k[2] = MK[2]^FK[2];
    k[3] = MK[3]^FK[3];
    
    for(unsigned long i = 0; i<=31; i++)
    {
        k[i+4] = k[i]^(linearTransformation(k[i+1]^k[i+2]^k[i+3]^CK[i]));
        rndKey[i] = k[i+4];
    }
}

void sm4_setkey_enc(sm4_context *ctx, unsigned char key[16])
{
    ctx->mode = ENCRYPT;
    sm4_keyExpansion(ctx->rk, key);
}

//sm4_setkey_dec: reversal of enc
void sm4_setkey_dec( sm4_context *ctx, unsigned char key[16] )
{
    int i;
    ctx->mode = DECRYPT;
    sm4_keyExpansion(ctx->rk, key);
    for(i = 0; i < 16; i++)
    {
        SWAP(ctx->rk[i], ctx->rk[31-i] );
    }
}

static unsigned long sm4Lt(unsigned long ka)
{
    unsigned long bb = 0;
    unsigned long c = 0;
    unsigned char a[4];
    unsigned char b[4];
    PUT_ULONG_BE(ka,a,0)
    b[0] = sm4Sbox(a[0]);
    b[1] = sm4Sbox(a[1]);
    b[2] = sm4Sbox(a[2]);
    b[3] = sm4Sbox(a[3]);
    GET_ULONG_BE(bb,b,0)
    c =bb^(ROTL(bb, 2))^(ROTL(bb, 10))^(ROTL(bb, 18))^(ROTL(bb, 24));
    return c;
}

static unsigned long sm4F(unsigned long x0,
                          unsigned long x1,
                          unsigned long x2,
                          unsigned long x3,
                          unsigned long rk)
{
    return (x0^sm4Lt(x1^x2^x3^rk));
}

static void sm4_one_round(unsigned long rk[32],
                          unsigned char input[16],
                          unsigned char output[16])
{
    unsigned long i = 0;
    unsigned long ulbuf[36];

    memset(ulbuf, 0, sizeof(ulbuf));
    GET_ULONG_BE( ulbuf[0], input, 0 )
    GET_ULONG_BE( ulbuf[1], input, 4 )
    GET_ULONG_BE( ulbuf[2], input, 8 )
    GET_ULONG_BE( ulbuf[3], input, 12 )
    while(i<32)
    {
        ulbuf[i+4] = sm4F(ulbuf[i], ulbuf[i+1], ulbuf[i+2], ulbuf[i+3], rk[i]);
        i++;
    }
    PUT_ULONG_BE(ulbuf[35],output,0);
    PUT_ULONG_BE(ulbuf[34],output,4);
    PUT_ULONG_BE(ulbuf[33],output,8);
    PUT_ULONG_BE(ulbuf[32],output,12);
}

//ECB encryption
void sm4_crypt_ecb(sm4_context *ctx,
                   int length,
                   unsigned char *plain,
                   unsigned char *cypher)
{
    while( length > 0 )
    {
        sm4_one_round(ctx->rk, plain, cypher );
        plain  += 16;
        cypher += 16;
        length -= 16;
    }

}

int main(void)
{
    unsigned long i;
    
    unsigned char key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    unsigned char plain[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    unsigned char cypher[16] = {0};

    sm4_context ctx;
    //encryption
    sm4_setkey_enc(&ctx, key);
    sm4_crypt_ecb(&ctx, 16, plain, cypher);
    //print cypher
    for(i=0;i<16;i++)
        printf("%02x ", cypher[i]);
    printf("\n");
    
    
    //decryption
    sm4_setkey_dec(&ctx,key);
    sm4_crypt_ecb(&ctx, 16, cypher, cypher);
    for(i=0;i<16;i++)
        printf("%02x ", cypher[i]);
    printf("\n");

    
    return 0;
}
