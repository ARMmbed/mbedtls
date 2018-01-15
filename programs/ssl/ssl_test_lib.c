/*
 *  Common code for SSL test programs
 *
 *  Copyright (C) 2018, ARM Limited, All Rights Reserved
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

#include "ssl_test_lib.h"

#ifdef POLARSSL_PROGRAMS_SSL__PREREQUISITES

void polarssl_ssl_test_debug( void *ctx, int level, const char *str )
{
    ((void) level);

    polarssl_fprintf( (FILE *) ctx, "%s", str );
    fflush(  (FILE *) ctx  );
}

/*
 * Test recv/send functions that make sure each try returns
 * WANT_READ/WANT_WRITE at least once before sucesseding
 */
int polarssl_ssl_test_recv( void *ctx, unsigned char *buf, size_t len )
{
    static int first_try = 1;
    int ret;

    if( first_try )
    {
        first_try = 0;
        return( POLARSSL_ERR_NET_WANT_READ );
    }

    ret = net_recv( ctx, buf, len );
    if( ret != POLARSSL_ERR_NET_WANT_READ )
        first_try = 1; /* Next call will be a new operation */
    return( ret );
}

int polarssl_ssl_test_send( void *ctx, const unsigned char *buf, size_t len )
{
    static int first_try = 1;
    int ret;

    if( first_try )
    {
        first_try = 0;
        return( POLARSSL_ERR_NET_WANT_WRITE );
    }

    ret = net_send( ctx, buf, len );
    if( ret != POLARSSL_ERR_NET_WANT_WRITE )
        first_try = 1; /* Next call will be a new operation */
    return( ret );
}

#define HEX2NUM( c )                    \
        if( c >= '0' && c <= '9' )      \
            c -= '0';                   \
        else if( c >= 'a' && c <= 'f' ) \
            c -= 'a' - 10;              \
        else if( c >= 'A' && c <= 'F' ) \
            c -= 'A' - 10;              \
        else                            \
            return( -1 );

/*
 * Convert a hex string to bytes.
 * Return 0 on success, -1 on error.
 */
int polarssl_ssl_test_unhexify( unsigned char *output, const char *input, size_t *olen )
{
    unsigned char c;
    size_t j;

    *olen = strlen( input );
    if( *olen % 2 != 0 || *olen / 2 > POLARSSL_PSK_MAX_LEN )
        return( -1 );
    *olen /= 2;

    for( j = 0; j < *olen * 2; j += 2 )
    {
        c = input[j];
        HEX2NUM( c );
        output[ j / 2 ] = c << 4;

        c = input[j + 1];
        HEX2NUM( c );
        output[ j / 2 ] |= c;
    }

    return( 0 );
}

int polarssl_ssl_test_forced_ciphersuite( int force_ciphersuite,
                                          int min_version,
                                          int max_version )
{
    const ssl_ciphersuite_t *ciphersuite_info;
    ciphersuite_info = ssl_ciphersuite_from_id( force_ciphersuite );

    if( max_version != -1 &&
        ciphersuite_info->min_minor_ver > max_version )
    {
        polarssl_printf("forced ciphersuite not allowed with this protocol version\n");
        return( 2 );
    }
    if( min_version != -1 &&
        ciphersuite_info->max_minor_ver < min_version )
    {
        polarssl_printf("forced ciphersuite not allowed with this protocol version\n");
        return( 2 );
    }

    /* If the server selects a version that's not supported by
     * this suite, then there will be no common ciphersuite... */
    if( max_version == -1 ||
        max_version > ciphersuite_info->max_minor_ver )
    {
        max_version = ciphersuite_info->max_minor_ver;
    }
    if( min_version < ciphersuite_info->min_minor_ver )
    {
        min_version = ciphersuite_info->min_minor_ver;
    }

    return( 0 );
}

#if defined(POLARSSL_SSL_SET_CURVES)
int polarssl_ssl_test_parse_curves( char *p,
                                    ecp_group_id *curve_list )
{
    int i = 0;
    const ecp_curve_info *curve_cur;
    const char *q;

    if( p == NULL )
        return( 0 );

    if( strcmp( p, "none" ) == 0 )
    {
        curve_list[0] = POLARSSL_ECP_DP_NONE;
    }
    else if( strcmp( p, "default" ) != 0 )
    {
        /* Leave room for a final NULL in curve list */
        while( i < CURVE_LIST_SIZE - 1 && *p != '\0' )
        {
            q = p;

            /* Terminate the current string */
            while( *p != ',' && *p != '\0' )
                p++;
            if( *p == ',' )
                *p++ = '\0';

            if( ( curve_cur = ecp_curve_info_from_name( q ) ) != NULL )
            {
                curve_list[i++] = curve_cur->grp_id;
            }
            else
            {
                polarssl_printf( "unknown curve %s\n", q );
                polarssl_printf( "supported curves: " );
                for( curve_cur = ecp_curve_list();
                     curve_cur->grp_id != POLARSSL_ECP_DP_NONE;
                     curve_cur++ )
                {
                    polarssl_printf( "%s ", curve_cur->name );
                }
                polarssl_printf( "\n" );
                return( 2 );
            }
        }

        polarssl_printf("Number of curves: %d\n", i );

        if( i == CURVE_LIST_SIZE - 1 && *p != '\0' )
        {
            polarssl_printf( "curves list too long, maximum %d",
                            CURVE_LIST_SIZE - 1 );
            return( 2 );
        }

        curve_list[i] = POLARSSL_ECP_DP_NONE;
    }

    return( 0 );
}
#endif /* POLARSSL_SSL_SET_CURVES */

#if defined(POLARSSL_SSL_ALPN)
int polarssl_ssl_test_parse_alpn( char *p,
                                  const char *alpn_list[] )
{
    int i = 0;
    if( p == NULL )
        return( 0 );

    /* Leave room for a final NULL in alpn_list */
    while( i < ALPN_LIST_SIZE - 1 && *p != '\0' )
    {
        alpn_list[i++] = p;

        /* Terminate the current string and move on to next one */
        while( *p != ',' && *p != '\0' )
            p++;
        if( *p == ',' )
            *p++ = '\0';
    }

    return( 0 );
}
#endif /* POLARSSL_SSL_ALPN */

#endif /* POLARSSL_PROGRAMS_SSL__PREREQUISITES */
