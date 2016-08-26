/*
 *  NIST SP800-38B compliant CMAC implementation
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/*
 * Definition of CMAC:
 * http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf
 * RFC 4493 "The AES-CMAC Algorithm"
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_CMAC_C)

#include "mbedtls/cmac.h"

#include <string.h>

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_AES_C)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST && MBEDTLS_AES_C */

/*
 * Macros for common operations.
 * Results in smaller compiled code than static inline functions.
 */

/*
 * XOR 128-bit
 */
#define XOR_128(i1, i2, o)                                                  \
    for( i = 0; i < 16; i++ )                                               \
        ( o )[i] = ( i1 )[i] ^ ( i2 )[i];

/*
 * Update the CMAC state in Mn using an input block x
 * TODO: Compiler optimisation
 */
#define UPDATE_CMAC( x )                                                    \
    XOR_128( Mn, ( x ), Mn );                                               \
    if( ( ret = mbedtls_cipher_update( &ctx->cipher_ctx, Mn, 16, Mn, &olen ) ) != 0 ) \
        return( ret );

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

/*
 * Initialize context
 */
void mbedtls_cmac_init( mbedtls_cmac_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_cmac_context ) );
}

/*
 * Leftshift a 16-byte block by 1 bit
 * \note output can be same as input
 */
static void leftshift_onebit(unsigned char *input, unsigned char *output)
{
    int i;
    unsigned char temp;
    unsigned char overflow = 0;

    for( i = 15; i >= 0; i-- )
    {
        temp = input[i];
        output[i] = temp << 1;
        output[i] |= overflow;
        overflow = temp >> 7;
    }
    return;
}

/*
 * Generate subkeys
 */
static int generate_subkeys(mbedtls_cmac_context *ctx)
{
    static const unsigned char Rb[2] = {0x00, 0x87}; /* Note - block size 16 only */
    int ret;
    unsigned char L[16];
    size_t olen;

    /* Calculate Ek(0) */
    memset( L, 0, 16 );
    if( ( ret = mbedtls_cipher_update( &ctx->cipher_ctx, L, 16, L, &olen ) ) != 0 )
    {
        return( ret );
    }

    /* 
     * Generate K1
     * If MSB(L) = 0, then K1 = (L << 1)
     * If MSB(L) = 1, then K1 = (L << 1) ^ Rb
     */
    leftshift_onebit( L, ctx->K1 );
    ctx->K1[15] ^= Rb[L[0] >> 7]; /* "Constant-time" operation */

    /*
     * Generate K2
     * If MSB(K1) == 0, then K2 = (K1 << 1)
     * If MSB(K1) == 1, then K2 = (K1 << 1) ^ Rb
     */
    leftshift_onebit( ctx->K1, ctx->K2 );
    ctx->K2[15] ^= Rb[ctx->K1[0] >> 7]; /* "Constant-time" operation */
    
    return( 0 );
}

int mbedtls_cmac_setkey( mbedtls_cmac_context *ctx,
                         mbedtls_cipher_id_t cipher,
                         const unsigned char *key,
                         unsigned int keybits )
{
    int ret;
    const mbedtls_cipher_info_t *cipher_info;

    cipher_info = mbedtls_cipher_info_from_values( cipher, keybits, MBEDTLS_MODE_ECB );
    if( cipher_info == NULL )
        return( MBEDTLS_ERR_CMAC_BAD_INPUT );

    if( cipher_info->block_size != 16 )
        return( MBEDTLS_ERR_CMAC_BAD_INPUT );

    mbedtls_cipher_free( &ctx->cipher_ctx );

    if( ( ret = mbedtls_cipher_setup( &ctx->cipher_ctx, cipher_info ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_cipher_setkey( &ctx->cipher_ctx, key, keybits,
                               MBEDTLS_ENCRYPT ) ) != 0 )
    {
        return( ret );
    }

    return( generate_subkeys(ctx) );
}

/*
 * Free context
 */
void mbedtls_cmac_free( mbedtls_cmac_context *ctx )
{
    mbedtls_cipher_free( &ctx->cipher_ctx );
    mbedtls_zeroize( ctx, sizeof( mbedtls_cmac_context ) );
}

/* TODO: Use cipher padding function? */
static void padding(const unsigned char *lastb, unsigned char *pad, const size_t length)
{
    size_t j;

    /* original last block */
    for( j = 0; j < 16; j++ )
    {
        if( j < length )
        {
            pad[j] = lastb[j];
        }
        else if( j == length )
        {
            pad[j] = 0x80;
        }
        else
        {
            pad[j] = 0x00;
        }
    }
}

/*
 * Generate tag on complete message
 */
static int cmac_generate( mbedtls_cmac_context *ctx, size_t length,
                          const unsigned char *input,
                          unsigned char *tag, size_t tag_len )
{
    unsigned char Mn[16];
    unsigned char M_last[16];
    unsigned char padded[16];
    int     n, i, j, ret, flag;
    size_t olen;

    /*
     * Check length requirements: SP800-38B A
     * 4 is a worst case bottom limit
     */
    if( tag_len < 4 || tag_len > 16 || tag_len % 2 != 0 )
        return( MBEDTLS_ERR_CMAC_BAD_INPUT );

    /* TODO: Use cipher padding function? */
    // mbedtls_cipher_set_padding_mode( ctx->cipher, MBEDTLS_PADDING_ONE_AND_ZEROS );

    n = ( length + 15 ) / 16;       /* n is number of rounds */

    if( n == 0 )
    {
        n = 1;
        flag = 0;
    }
    else
    {
        flag = ( ( length % 16 ) == 0);
    }

    /* Calculate last block */
    if( flag )
    {
        /* Last block is complete block */
        XOR_128( &input[16 * (n - 1)], ctx->K1, M_last );
    }
    else
    {
        /* TODO: Use cipher padding function? */
        padding( &input[16 * (n - 1)], padded, length % 16 );
        XOR_128( padded, ctx->K2, M_last );
    }

    memset( Mn, 0, 16 );

    for( j = 0; j < n - 1; j++ )
    {
        UPDATE_CMAC(&input[16 * j]);
    }

    UPDATE_CMAC(M_last);

    memcpy( tag, Mn, 16 );

    return( 0 );
}

int mbedtls_cmac_generate( mbedtls_cmac_context *ctx, size_t length,
                           const unsigned char *input,
                           unsigned char *tag, size_t tag_len )
{
    return( cmac_generate( ctx, length, input, tag, tag_len ) );
}

/*
 * Authenticated decryption
 */
int mbedtls_cmac_verify( mbedtls_cmac_context *ctx, size_t length,
                         const unsigned char *input,
                         const unsigned char *tag, size_t tag_len )
{
    int ret;
    unsigned char check_tag[16];
    unsigned char i;
    int diff;
    
    if( ( ret = cmac_generate( ctx, length, input, check_tag, tag_len) ) != 0 )
    {
        return ret;
    }

    /* Check tag in "constant-time" */
    for( diff = 0, i = 0; i < tag_len; i++ )
    {
        diff |= tag[i] ^ check_tag[i];
    }

    if( diff != 0 )
    {
        return( MBEDTLS_ERR_CMAC_VERIFY_FAILED );
    }

    return( 0 );
}

int mbedtls_aes_cmac_prf_128( mbedtls_cmac_context *ctx, size_t length,
                              const unsigned char *key, size_t key_length,
                              const unsigned char *input,
                              unsigned char *tag )
{
    int ret;
    unsigned char zero_key[16];
    unsigned char int_key[16];

    if( key_length == 16 )
    {
        /* Use key as is */
        memcpy(int_key, key, 16);
    }
    else
    {
        mbedtls_cmac_context zero_ctx;

        /* Key is AES_CMAC(0, key) */
        mbedtls_cmac_init( &zero_ctx );
        memset(zero_key, 0, 16);
        ret = mbedtls_cmac_setkey( &zero_ctx, MBEDTLS_CIPHER_ID_AES, zero_key, 8 * sizeof zero_key );
        if( ret != 0 )
        {
            return( ret );
        }
        ret = mbedtls_cmac_generate( &zero_ctx, key_length, key, int_key, 16 );
        if( ret != 0 )
        {
            return( ret );
        }
    }

    ret = mbedtls_cmac_setkey( ctx, MBEDTLS_CIPHER_ID_AES, int_key, 8 * sizeof int_key );
    if( ret != 0 )
    {
        return( ret );
    }
    return( mbedtls_cmac_generate( ctx, length, input, tag, 16 ) );
}

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_AES_C)
/*
 * Examples 1 to 4 from SP800-3B corrected Appendix D.1
 * http://csrc.nist.gov/publications/nistpubs/800-38B/Updated_CMAC_Examples.pdf
 */

#define NB_CMAC_TESTS 4
#define NB_PRF_TESTS 3

/* Key */
static const unsigned char key[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

/* Assume we don't need to test Ek0 as this is a function of the cipher */

/* Subkey K1 */
static const unsigned char K1[] = {
    0xfb, 0xee, 0xd6, 0x18, 0x35, 0x71, 0x33, 0x66,
    0x7c, 0x85, 0xe0, 0x8f, 0x72, 0x36, 0xa8, 0xde
};

/* Subkey K2 */
static const unsigned char K2[] = {
    0xf7, 0xdd, 0xac, 0x30, 0x6a, 0xe2, 0x66, 0xcc,
    0xf9, 0x0b, 0xc1, 0x1e, 0xe4, 0x6d, 0x51, 0x3b
};

/* All Messages */
static const unsigned char M[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};

static const unsigned char T[NB_CMAC_TESTS][16] = {
    {
        0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
        0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46
    },
    {
        0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
        0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c
    },
    {
        0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
        0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27
    },
    {
        0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
        0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe
    }
};

/* Sizes in bytes */
static const size_t Mlen[NB_CMAC_TESTS] = {
    0,
    16,
    40,
    64
};

/* PRF K */
static const unsigned char PRFK[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0xed, 0xcb
};

/* Sizes in bytes */
static const size_t PRFKlen[NB_PRF_TESTS] = {
    18,
    16,
    10
};

/* PRF M */
static const unsigned char PRFM[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13    
};

static const unsigned char PRFT[NB_PRF_TESTS][16] = {
    {
        0x84, 0xa3, 0x48, 0xa4, 0xa4, 0x5d, 0x23, 0x5b,
        0xab, 0xff, 0xfc, 0x0d, 0x2b, 0x4d, 0xa0, 0x9a
    },
    {
        0x98, 0x0a, 0xe8, 0x7b, 0x5f, 0x4c, 0x9c, 0x52,
        0x14, 0xf5, 0xb6, 0xa8, 0x45, 0x5e, 0x4c, 0x2d
    },
    {
        0x29, 0x0d, 0x9e, 0x11, 0x2e, 0xdb, 0x09, 0xee,
        0x14, 0x1f, 0xcf, 0x64, 0xc0, 0xb7, 0x2f, 0x3d
    }
};


int mbedtls_cmac_self_test( int verbose )
{
    mbedtls_cmac_context ctx;
    unsigned char tag[16];
    int i;
    int ret;

    mbedtls_cmac_init( &ctx );

    if( mbedtls_cmac_setkey( &ctx, MBEDTLS_CIPHER_ID_AES, key, 8 * sizeof key ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "  CMAC: setup failed" );

        return( 1 );
    }

    if( ( memcmp( ctx.K1, K1, 16 ) != 0 ) ||
        ( memcmp( ctx.K2, K2, 16 ) != 0 ) )
    {
        if( verbose != 0 )
            mbedtls_printf( "  CMAC: subkey generation failed" );

        return( 1 );
    }

    for( i = 0; i < NB_CMAC_TESTS; i++ )
    {
        mbedtls_printf( "  AES-128-CMAC #%u: ", i );
        
        ret = mbedtls_cmac_generate( &ctx, Mlen[i], M, tag, 16 );
        if( ret != 0 ||
            memcmp( tag, T[i], 16 ) != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            return( 1 );
        }
        ret = mbedtls_cmac_verify( &ctx, Mlen[i], M, T[i], 16 );
        if( ret != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            return( 1 );
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

    for( i = 0; i < NB_PRF_TESTS; i++ )
    {
        mbedtls_printf( "  AES-CMAC-128-PRF #%u: ", i );

        mbedtls_aes_cmac_prf_128( &ctx, 20, PRFK, PRFKlen[i], PRFM, tag);
        
        if( ret != 0 ||
            memcmp( tag, PRFT[i], 16 ) != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            return( 1 );
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

    mbedtls_cmac_free( &ctx );

    if( verbose != 0 )
        mbedtls_printf( "\n" );

    return( 0 );
}

#endif /* MBEDTLS_SELF_TEST && MBEDTLS_AES_C */

#endif /* MBEDTLS_CMAC_C */
