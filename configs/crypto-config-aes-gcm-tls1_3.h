/**
 * \file crypto-config-aes-gcm-tls1_3.h
 *
 * \brief Minimal crypto configuration for a TLS 1.3 only client with AES-GCM ciphersuites
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/**
 * To be used in conjunction with configs/config-aes-gcm-tls1_3.h */

#ifndef PSA_CRYPTO_CONFIG_H
#define PSA_CRYPTO_CONFIG_H

#define PSA_WANT_ALG_GCM                        1
#define PSA_WANT_ALG_ECDH                       1
#define PSA_WANT_ALG_ECDSA                      1
#define PSA_WANT_ALG_SHA_256                    1
#define PSA_WANT_ALG_SHA_384                    1
#define PSA_WANT_ALG_HKDF_EXPAND                1
#define PSA_WANT_ALG_HKDF_EXTRACT               1
#define PSA_WANT_ECC_SECP_R1_256                1

#define PSA_WANT_KEY_TYPE_AES                   1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC    1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE 1

#endif /* PSA_CRYPTO_CONFIG_H */
