/*
 *  Common code library for SSL test programs.
 *
 *  In addition to the functions in this file, there is shared source code
 *  that cannot be compiled separately in "ssl_test_common_source.c".
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS

#include "ssl_test_lib.h"

#if defined(MBEDTLS_TEST_HOOKS)
#include "test/threading_helpers.h"
#endif

#if !defined(MBEDTLS_SSL_TEST_IMPOSSIBLE)

#define ARRAY_LENGTH(x)     (sizeof(x)/sizeof(x[0]))

void my_debug(void *ctx, int level,
              const char *file, int line,
              const char *str)
{
    const char *p, *basename;

    /* Extract basename from file */
    for (p = basename = file; *p != '\0'; p++) {
        if (*p == '/' || *p == '\\') {
            basename = p + 1;
        }
    }

    mbedtls_fprintf((FILE *) ctx, "%s:%04d: |%d| %s",
                    basename, line, level, str);
    fflush((FILE *) ctx);
}

#if defined(MBEDTLS_HAVE_TIME)
mbedtls_time_t dummy_constant_time(mbedtls_time_t *time)
{
    (void) time;
    return 0x5af2a056;
}
#endif

int rng_seed(int reproducible, const char *pers)
{
    /* The PSA crypto RNG does its own seeding. */
    (void) pers;
    if (reproducible) {
        mbedtls_fprintf(stderr,
                        "The PSA RNG does not support reproducible mode.\n");
        return -1;
    }
    return 0;
}

int key_opaque_alg_parse(const char *arg, const char **alg1, const char **alg2)
{
    char *separator;
    if ((separator = strchr(arg, ',')) == NULL) {
        return 1;
    }
    *separator = '\0';

    *alg1 = arg;
    *alg2 = separator + 1;

    if (strcmp(*alg1, "rsa-sign-pkcs1") != 0 &&
        strcmp(*alg1, "rsa-sign-pss") != 0 &&
        strcmp(*alg1, "rsa-sign-pss-sha256") != 0 &&
        strcmp(*alg1, "rsa-sign-pss-sha384") != 0 &&
        strcmp(*alg1, "rsa-sign-pss-sha512") != 0 &&
        strcmp(*alg1, "ecdsa-sign") != 0 &&
        strcmp(*alg1, "ecdh") != 0) {
        return 1;
    }

    if (strcmp(*alg2, "rsa-sign-pkcs1") != 0 &&
        strcmp(*alg2, "rsa-sign-pss") != 0 &&
        strcmp(*alg1, "rsa-sign-pss-sha256") != 0 &&
        strcmp(*alg1, "rsa-sign-pss-sha384") != 0 &&
        strcmp(*alg1, "rsa-sign-pss-sha512") != 0 &&
        strcmp(*alg2, "ecdsa-sign") != 0 &&
        strcmp(*alg2, "ecdh") != 0 &&
        strcmp(*alg2, "none") != 0) {
        return 1;
    }

    return 0;
}

int key_opaque_set_alg_usage(const char *alg1, const char *alg2,
                             psa_algorithm_t *psa_alg1,
                             psa_algorithm_t *psa_alg2,
                             psa_key_usage_t *usage,
                             mbedtls_pk_type_t key_type)
{
    if (strcmp(alg1, "none") != 0) {
        const char *algs[] = { alg1, alg2 };
        psa_algorithm_t *psa_algs[] = { psa_alg1, psa_alg2 };

        for (int i = 0; i < 2; i++) {
            if (strcmp(algs[i], "rsa-sign-pkcs1") == 0) {
                *psa_algs[i] = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_ANY_HASH);
                *usage |= PSA_KEY_USAGE_SIGN_HASH;
            } else if (strcmp(algs[i], "rsa-sign-pss") == 0) {
                *psa_algs[i] = PSA_ALG_RSA_PSS(PSA_ALG_ANY_HASH);
                *usage |= PSA_KEY_USAGE_SIGN_HASH;
            } else if (strcmp(algs[i], "rsa-sign-pss-sha256") == 0) {
                *psa_algs[i] = PSA_ALG_RSA_PSS(PSA_ALG_SHA_256);
                *usage |= PSA_KEY_USAGE_SIGN_HASH;
            } else if (strcmp(algs[i], "rsa-sign-pss-sha384") == 0) {
                *psa_algs[i] = PSA_ALG_RSA_PSS(PSA_ALG_SHA_384);
                *usage |= PSA_KEY_USAGE_SIGN_HASH;
            } else if (strcmp(algs[i], "rsa-sign-pss-sha512") == 0) {
                *psa_algs[i] = PSA_ALG_RSA_PSS(PSA_ALG_SHA_512);
                *usage |= PSA_KEY_USAGE_SIGN_HASH;
            } else if (strcmp(algs[i], "ecdsa-sign") == 0) {
                *psa_algs[i] = MBEDTLS_PK_ALG_ECDSA(PSA_ALG_ANY_HASH);
                *usage |= PSA_KEY_USAGE_SIGN_HASH;
            } else if (strcmp(algs[i], "ecdh") == 0) {
                *psa_algs[i] = PSA_ALG_ECDH;
                *usage |= PSA_KEY_USAGE_DERIVE;
            } else if (strcmp(algs[i], "none") == 0) {
                *psa_algs[i] = PSA_ALG_NONE;
            }
        }
    } else {
        if (key_type == MBEDTLS_PK_ECKEY) {
            *psa_alg1 = MBEDTLS_PK_ALG_ECDSA(PSA_ALG_ANY_HASH);
            *psa_alg2 = PSA_ALG_ECDH;
            *usage = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_DERIVE;
        } else if (key_type == MBEDTLS_PK_RSA) {
            *psa_alg1 = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_ANY_HASH);
            *psa_alg2 = PSA_ALG_RSA_PSS(PSA_ALG_ANY_HASH);
            *usage = PSA_KEY_USAGE_SIGN_HASH;
        } else {
            return 1;
        }
    }

    return 0;
}

#if defined(MBEDTLS_PK_C)
int pk_wrap_as_opaque(mbedtls_pk_context *pk, psa_algorithm_t psa_alg, psa_algorithm_t psa_alg2,
                      psa_key_usage_t psa_usage, mbedtls_svc_key_id_t *key_id)
{
    int ret;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;

    ret = mbedtls_pk_get_psa_attributes(pk, PSA_KEY_USAGE_SIGN_HASH, &key_attr);
    if (ret != 0) {
        return ret;
    }
    psa_set_key_usage_flags(&key_attr, psa_usage);
    psa_set_key_algorithm(&key_attr, psa_alg);
    if (psa_alg2 != PSA_ALG_NONE) {
        psa_set_key_enrollment_algorithm(&key_attr, psa_alg2);
    }
    ret = mbedtls_pk_import_into_psa(pk, &key_attr, key_id);
    if (ret != 0) {
        return ret;
    }
    mbedtls_pk_free(pk);
    mbedtls_pk_init(pk);
    ret = mbedtls_pk_wrap_psa(pk, *key_id);
    if (ret != 0) {
        return ret;
    }

    return 0;
}
#endif /* MBEDTLS_PK_C */

#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
int ca_callback(void *data, mbedtls_x509_crt const *child,
                mbedtls_x509_crt **candidates)
{
    int ret = 0;
    mbedtls_x509_crt *ca = (mbedtls_x509_crt *) data;
    mbedtls_x509_crt *first;

    /* This is a test-only implementation of the CA callback
     * which always returns the entire list of trusted certificates.
     * Production implementations managing a large number of CAs
     * should use an efficient presentation and lookup for the
     * set of trusted certificates (such as a hashtable) and only
     * return those trusted certificates which satisfy basic
     * parental checks, such as the matching of child `Issuer`
     * and parent `Subject` field or matching key identifiers. */
    ((void) child);

    first = mbedtls_calloc(1, sizeof(mbedtls_x509_crt));
    if (first == NULL) {
        ret = -1;
        goto exit;
    }
    mbedtls_x509_crt_init(first);

    if (mbedtls_x509_crt_parse_der(first, ca->raw.p, ca->raw.len) != 0) {
        ret = -1;
        goto exit;
    }

    while (ca->next != NULL) {
        ca = ca->next;
        if (mbedtls_x509_crt_parse_der(first, ca->raw.p, ca->raw.len) != 0) {
            ret = -1;
            goto exit;
        }
    }

exit:

    if (ret != 0) {
        mbedtls_x509_crt_free(first);
        mbedtls_free(first);
        first = NULL;
    }

    *candidates = first;
    return ret;
}
#endif /* MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK */

int delayed_recv(void *ctx, unsigned char *buf, size_t len)
{
    static int first_try = 1;
    int ret;

    if (first_try) {
        first_try = 0;
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    ret = mbedtls_net_recv(ctx, buf, len);
    if (ret != MBEDTLS_ERR_SSL_WANT_READ) {
        first_try = 1; /* Next call will be a new operation */
    }
    return ret;
}

int delayed_send(void *ctx, const unsigned char *buf, size_t len)
{
    static int first_try = 1;
    int ret;

    if (first_try) {
        first_try = 0;
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }

    ret = mbedtls_net_send(ctx, buf, len);
    if (ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
        first_try = 1; /* Next call will be a new operation */
    }
    return ret;
}

#if !defined(MBEDTLS_TIMING_C)
int idle(mbedtls_net_context *fd,
         int idle_reason)
#else
int idle(mbedtls_net_context *fd,
         mbedtls_timing_delay_context *timer,
         int idle_reason)
#endif
{
    int ret;
    int poll_type = 0;

    if (idle_reason == MBEDTLS_ERR_SSL_WANT_WRITE) {
        poll_type = MBEDTLS_NET_POLL_WRITE;
    } else if (idle_reason == MBEDTLS_ERR_SSL_WANT_READ) {
        poll_type = MBEDTLS_NET_POLL_READ;
    }
#if !defined(MBEDTLS_TIMING_C)
    else {
        return 0;
    }
#endif

    while (1) {
        /* Check if timer has expired */
#if defined(MBEDTLS_TIMING_C)
        if (timer != NULL &&
            mbedtls_timing_get_delay(timer) == 2) {
            break;
        }
#endif /* MBEDTLS_TIMING_C */

        /* Check if underlying transport became available */
        if (poll_type != 0) {
            ret = mbedtls_net_poll(fd, poll_type, 0);
            if (ret < 0) {
                return ret;
            }
            if (ret == poll_type) {
                break;
            }
        }
    }

    return 0;
}

#if defined(MBEDTLS_TEST_HOOKS)

void test_hooks_init(void)
{
    mbedtls_test_info_reset();

#if defined(MBEDTLS_TEST_MUTEX_USAGE)
    mbedtls_test_mutex_usage_init();
#endif
}

int test_hooks_failure_detected(void)
{
#if defined(MBEDTLS_TEST_MUTEX_USAGE)
    /* Errors are reported via mbedtls_test_info. */
    mbedtls_test_mutex_usage_check();
#endif

    if (mbedtls_test_get_result() != MBEDTLS_TEST_RESULT_SUCCESS) {
        return 1;
    }
    return 0;
}

void test_hooks_free(void)
{
#if defined(MBEDTLS_TEST_MUTEX_USAGE)
    mbedtls_test_mutex_usage_end();
#endif
}

#endif /* MBEDTLS_TEST_HOOKS */

static const struct {
    uint16_t tls_id;
    const char *name;
    uint8_t is_supported;
} tls_id_group_name_table[] =
{
#if defined(PSA_WANT_ECC_SECP_R1_521)
    { MBEDTLS_SSL_IANA_TLS_GROUP_SECP521R1, "secp521r1", 1 },
#else
    { MBEDTLS_SSL_IANA_TLS_GROUP_SECP521R1, "secp521r1", 0 },
#endif
#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_512)
    { MBEDTLS_SSL_IANA_TLS_GROUP_BP512R1, "brainpoolP512r1", 1 },
#else
    { MBEDTLS_SSL_IANA_TLS_GROUP_BP512R1, "brainpoolP512r1", 0 },
#endif
#if defined(PSA_WANT_ECC_SECP_R1_384)
    { MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1, "secp384r1", 1 },
#else
    { MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1, "secp384r1", 0 },
#endif
#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_384)
    { MBEDTLS_SSL_IANA_TLS_GROUP_BP384R1, "brainpoolP384r1", 1 },
#else
    { MBEDTLS_SSL_IANA_TLS_GROUP_BP384R1, "brainpoolP384r1", 0 },
#endif
#if defined(PSA_WANT_ECC_SECP_R1_256)
    { MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1, "secp256r1", 1 },
#else
    { MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1, "secp256r1", 0 },
#endif
#if defined(PSA_WANT_ECC_SECP_K1_256)
    { MBEDTLS_SSL_IANA_TLS_GROUP_SECP256K1, "secp256k1", 1 },
#else
    { MBEDTLS_SSL_IANA_TLS_GROUP_SECP256K1, "secp256k1", 0 },
#endif
#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_256)
    { MBEDTLS_SSL_IANA_TLS_GROUP_BP256R1, "brainpoolP256r1", 1 },
#else
    { MBEDTLS_SSL_IANA_TLS_GROUP_BP256R1, "brainpoolP256r1", 0 },
#endif
#if defined(PSA_WANT_ECC_MONTGOMERY_255)
    { MBEDTLS_SSL_IANA_TLS_GROUP_X25519, "x25519", 1 },
#else
    { MBEDTLS_SSL_IANA_TLS_GROUP_X25519, "x25519", 0 },
#endif
#if defined(PSA_WANT_ECC_MONTGOMERY_448)
    { MBEDTLS_SSL_IANA_TLS_GROUP_X448, "x448", 1 },
#else
    { MBEDTLS_SSL_IANA_TLS_GROUP_X448, "x448", 0 },
#endif
#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_EPHEMERAL_ENABLED) && \
    defined(PSA_WANT_ALG_FFDH)
#if defined(PSA_WANT_DH_RFC7919_2048)
    { MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE2048, "ffdhe2048", 1 },
#else /* PSA_WANT_DH_RFC7919_2048 */
    { MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE2048, "ffdhe2048", 0 },
#endif /* PSA_WANT_DH_RFC7919_2048 */
#if defined(PSA_WANT_DH_RFC7919_3072)
    { MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE3072, "ffdhe3072", 1 },
#else /* PSA_WANT_DH_RFC7919_3072 */
    { MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE3072, "ffdhe3072", 0 },
#endif /* PSA_WANT_DH_RFC7919_3072 */
#if defined(PSA_WANT_DH_RFC7919_4096)
    { MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE4096, "ffdhe4096", 1 },
#else /* PSA_WANT_DH_RFC7919_4096 */
    { MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE4096, "ffdhe4096", 0 },
#endif /* PSA_WANT_DH_RFC7919_4096 */
#if defined(PSA_WANT_DH_RFC7919_6144)
    { MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE6144, "ffdhe6144", 1 },
#else /* PSA_WANT_DH_RFC7919_6144 */
    { MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE6144, "ffdhe6144", 0 },
#endif /* PSA_WANT_DH_RFC7919_6144 */
#if defined(PSA_WANT_DH_RFC7919_8192)
    { MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE8192, "ffdhe8192", 1 },
#else /* PSA_WANT_DH_RFC7919_8192 */
    { MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE8192, "ffdhe8192", 0 },
#endif /* PSA_WANT_DH_RFC7919_8192 */
#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_EPHEMERAL_ENABLED && PSA_WANT_ALG_FFDH */
    { 0, NULL, 0 },
};

static uint16_t mbedtls_ssl_get_curve_tls_id_from_name(const char *name)
{
    if (name == NULL) {
        return 0;
    }

    for (int i = 0; tls_id_group_name_table[i].tls_id != 0; i++) {
        if (strcmp(tls_id_group_name_table[i].name, name) == 0) {
            return tls_id_group_name_table[i].tls_id;
        }
    }

    return 0;
}

static void mbedtls_ssl_print_supported_groups_list(void)
{
    for (int i = 0; tls_id_group_name_table[i].tls_id != 0; i++) {
        if (tls_id_group_name_table[i].is_supported == 1) {
            mbedtls_printf("%s ", tls_id_group_name_table[i].name);
        }
    }
}

int parse_groups(const char *groups, uint16_t *group_list, size_t group_list_len)
{
    char *p = (char *) groups;
    char *q = NULL;
    size_t i = 0;

    if (strcmp(p, "none") == 0) {
        group_list[0] = 0;
    } else if (strcmp(p, "default") != 0) {
        /* Leave room for a final NULL in group list */
        while (i < group_list_len - 1 && *p != '\0') {
            uint16_t curve_tls_id;
            q = p;

            /* Terminate the current string */
            while (*p != ',' && *p != '\0') {
                p++;
            }
            if (*p == ',') {
                *p++ = '\0';
            }

            if ((curve_tls_id = mbedtls_ssl_get_curve_tls_id_from_name(q)) != 0) {
                group_list[i++] = curve_tls_id;
            } else {
                mbedtls_printf("unknown group %s\n", q);
                mbedtls_printf("supported groups: ");
                mbedtls_ssl_print_supported_groups_list();
                mbedtls_printf("\n");
                return -1;
            }
        }

        mbedtls_printf("Number of groups: %u\n", (unsigned int) i);

        if (i == group_list_len - 1 && *p != '\0') {
            mbedtls_printf("groups list too long, maximum %u",
                           (unsigned int) (group_list_len - 1));
            return -1;
        }

        group_list[i] = 0;
    }

    return 0;
}


void mbedtls_print_supported_sig_algs(void)
{
    mbedtls_printf("supported signature algorithms:\n");
    mbedtls_printf("\trsa_pkcs1_sha256 ");
    mbedtls_printf("rsa_pkcs1_sha384 ");
    mbedtls_printf("rsa_pkcs1_sha512\n");
    mbedtls_printf("\tecdsa_secp256r1_sha256 ");
    mbedtls_printf("ecdsa_secp384r1_sha384 ");
    mbedtls_printf("ecdsa_secp521r1_sha512\n");
    mbedtls_printf("\trsa_pss_rsae_sha256 ");
    mbedtls_printf("rsa_pss_rsae_sha384 ");
    mbedtls_printf("rsa_pss_rsae_sha512\n");
    mbedtls_printf("\trsa_pss_pss_sha256 ");
    mbedtls_printf("rsa_pss_pss_sha384 ");
    mbedtls_printf("rsa_pss_pss_sha512\n");
    mbedtls_printf("\ted25519 ");
    mbedtls_printf("ed448 ");
    mbedtls_printf("rsa_pkcs1_sha1 ");
    mbedtls_printf("ecdsa_sha1\n");
    mbedtls_printf("\n");
}

static int sig_alg_hex_digit(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

int parse_sig_algs(const char *sig_algs, uint16_t *sig_alg_list,
                   size_t sig_alg_list_len)
{
    typedef struct {
        const char *name;
        uint16_t id;
    } sig_alg_name_t;

    static const sig_alg_name_t sig_alg_names[] = {
        { "rsa_pkcs1_sha256", MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA256 },
        { "rsa_pkcs1_sha384", MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA384 },
        { "rsa_pkcs1_sha512", MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA512 },
        { "ecdsa_secp256r1_sha256", MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256 },
        { "ecdsa_secp384r1_sha384", MBEDTLS_TLS1_3_SIG_ECDSA_SECP384R1_SHA384 },
        { "ecdsa_secp521r1_sha512", MBEDTLS_TLS1_3_SIG_ECDSA_SECP521R1_SHA512 },
        { "rsa_pss_rsae_sha256", MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA256 },
        { "rsa_pss_rsae_sha384", MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA384 },
        { "rsa_pss_rsae_sha512", MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA512 },
        { "ed25519", MBEDTLS_TLS1_3_SIG_ED25519 },
        { "ed448", MBEDTLS_TLS1_3_SIG_ED448 },
        { "rsa_pss_pss_sha256", MBEDTLS_TLS1_3_SIG_RSA_PSS_PSS_SHA256 },
        { "rsa_pss_pss_sha384", MBEDTLS_TLS1_3_SIG_RSA_PSS_PSS_SHA384 },
        { "rsa_pss_pss_sha512", MBEDTLS_TLS1_3_SIG_RSA_PSS_PSS_SHA512 },
        { "rsa_pkcs1_sha1", MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA1 },
        { "ecdsa_sha1", MBEDTLS_TLS1_3_SIG_ECDSA_SHA1 },
    };

    const char *p = sig_algs;
    size_t i = 0;

    /* Leave room for a final MBEDTLS_TLS1_3_SIG_NONE in sig_alg_list. */
    while (i < sig_alg_list_len - 1 && *p != '\0') {
        size_t name_len = strcspn(p, ",");
        uint16_t sig_alg = 0;
        size_t j;
        int found = 0;

        if (name_len == 4) {
            /* A TLS 1.2 (hash, signature) pair given as 4 hex digits. */
            int d0 = sig_alg_hex_digit(p[0]);
            int d1 = sig_alg_hex_digit(p[1]);
            int d2 = sig_alg_hex_digit(p[2]);
            int d3 = sig_alg_hex_digit(p[3]);

            if (d0 >= 0 && d1 >= 0 && d2 >= 0 && d3 >= 0) {
                sig_alg = (uint16_t) ((d0 << 12) | (d1 << 8) |
                                      (d2 << 4) | d3);
                found = 1;
            }
        }

        if (!found) {
            for (j = 0; j < ARRAY_LENGTH(sig_alg_names); j++) {
                if (strlen(sig_alg_names[j].name) == name_len &&
                    strncmp(p, sig_alg_names[j].name, name_len) == 0) {
                    sig_alg = sig_alg_names[j].id;
                    found = 1;
                    break;
                }
            }
        }

        if (!found) {
            mbedtls_printf("unknown signature algorithm \"%.*s\"\n",
                           (int) name_len, p);
            mbedtls_print_supported_sig_algs();
            return -1;
        }

        sig_alg_list[i++] = sig_alg;
        p += name_len;
        if (*p == ',') {
            p++;
        }
    }

    if (i == sig_alg_list_len - 1 && *p != '\0') {
        mbedtls_printf("signature algorithm list too long, maximum %u",
                       (unsigned int) (sig_alg_list_len - 1));
        return -1;
    }

    sig_alg_list[i] = MBEDTLS_TLS1_3_SIG_NONE;
    return 0;
}

#endif /* !defined(MBEDTLS_SSL_TEST_IMPOSSIBLE) */
