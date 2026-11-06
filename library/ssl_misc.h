/**
 * \file ssl_misc.h
 *
 * \brief Internal functions shared by the SSL modules
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_SSL_MISC_H
#define MBEDTLS_SSL_MISC_H

#include "mbedtls_common.h"
#include "mbedtls/build_info.h"

#include "ssl_types.h"
#include "ssl_debug_helpers.h"

#include "mbedtls/error.h"

#include "mbedtls/ssl.h"
#include "mbedtls/debug.h"
#include "debug_internal.h"

#include "psa/crypto.h"
#include "psa_util_internal.h" // for mbedtls_error_pair_t, psa_status_to_mbedtls
extern const mbedtls_error_pair_t psa_to_ssl_errors[7];

#include "mbedtls/pk.h"
#include "ssl_ciphersuites_internal.h"
#include "x509_internal.h"

/*
 * Helper macros for function call with return check.
 */
/*
 * Exit when return non-zero value
 */
#define MBEDTLS_SSL_PROC_CHK(f)                               \
    do {                                                        \
        ret = (f);                                            \
        if (ret != 0)                                          \
        {                                                       \
            goto cleanup;                                       \
        }                                                       \
    } while (0)
/*
 * Exit when return negative value
 */
#define MBEDTLS_SSL_PROC_CHK_NEG(f)                           \
    do {                                                        \
        ret = (f);                                            \
        if (ret < 0)                                           \
        {                                                       \
            goto cleanup;                                       \
        }                                                       \
    } while (0)

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
/**
 * \brief          Return the maximum fragment length (payload, in bytes) for
 *                 the output buffer. For the client, this is the configured
 *                 value. For the server, it is the minimum of two - the
 *                 configured value and the negotiated one.
 *
 * \sa             mbedtls_ssl_conf_max_frag_len()
 * \sa             mbedtls_ssl_get_max_out_record_payload()
 *
 * \param ssl      SSL context
 *
 * \return         Current maximum fragment length for the output buffer.
 */
size_t mbedtls_ssl_get_output_max_frag_len(const mbedtls_ssl_context *ssl);

/**
 * \brief          Return the maximum fragment length (payload, in bytes) for
 *                 the input buffer. This is the negotiated maximum fragment
 *                 length, or, if there is none, MBEDTLS_SSL_IN_CONTENT_LEN.
 *                 If it is not defined either, the value is 2^14. This function
 *                 works as its predecessor, \c mbedtls_ssl_get_max_frag_len().
 *
 * \sa             mbedtls_ssl_conf_max_frag_len()
 * \sa             mbedtls_ssl_get_max_in_record_payload()
 *
 * \param ssl      SSL context
 *
 * \return         Current maximum fragment length for the output buffer.
 */
size_t mbedtls_ssl_get_input_max_frag_len(const mbedtls_ssl_context *ssl);
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(MBEDTLS_SSL_RECORD_SIZE_LIMIT)
/**
 * \brief    Get the size limit in bytes for the protected outgoing records
 *           as defined in RFC 8449
 *
 * \param ssl      SSL context
 *
 * \return         The size limit in bytes for the protected outgoing
 *                 records as defined in RFC 8449.
 */
size_t mbedtls_ssl_get_output_record_size_limit(const mbedtls_ssl_context *ssl);
#endif /* MBEDTLS_SSL_RECORD_SIZE_LIMIT */

#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
static inline size_t mbedtls_ssl_get_output_buflen(const mbedtls_ssl_context *ctx)
{
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    return mbedtls_ssl_get_output_max_frag_len(ctx)
           + MBEDTLS_SSL_HEADER_LEN + MBEDTLS_SSL_PAYLOAD_OVERHEAD
           + MBEDTLS_SSL_CID_OUT_LEN_MAX;
#else
    return mbedtls_ssl_get_output_max_frag_len(ctx)
           + MBEDTLS_SSL_HEADER_LEN + MBEDTLS_SSL_PAYLOAD_OVERHEAD;
#endif
}

static inline size_t mbedtls_ssl_get_input_buflen(const mbedtls_ssl_context *ctx)
{
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    return mbedtls_ssl_get_input_max_frag_len(ctx)
           + MBEDTLS_SSL_HEADER_LEN + MBEDTLS_SSL_PAYLOAD_OVERHEAD
           + MBEDTLS_SSL_CID_IN_LEN_MAX;
#else
    return mbedtls_ssl_get_input_max_frag_len(ctx)
           + MBEDTLS_SSL_HEADER_LEN + MBEDTLS_SSL_PAYLOAD_OVERHEAD;
#endif
}
#endif

/*
 * TLS extension flags (for extensions with outgoing ServerHello content
 * that need it (e.g. for RENEGOTIATION_INFO the server already knows because
 * of state of the renegotiation flag, so no indicator is required)
 */
#define MBEDTLS_TLS_EXT_SUPPORTED_POINT_FORMATS_PRESENT (1 << 0)
#define MBEDTLS_TLS_EXT_ECJPAKE_KKPP_OK                 (1 << 1)

/**
 * \brief        This function checks if the remaining size in a buffer is
 *               greater or equal than a needed space.
 *
 * \param cur    Pointer to the current position in the buffer.
 * \param end    Pointer to one past the end of the buffer.
 * \param need   Needed space in bytes.
 *
 * \return       Zero if the needed space is available in the buffer, non-zero
 *               otherwise.
 */
#if !defined(MBEDTLS_TEST_HOOKS)
static inline int mbedtls_ssl_chk_buf_ptr(const uint8_t *cur,
                                          const uint8_t *end, size_t need)
{
    return (cur > end) || (need > (size_t) (end - cur));
}
#else
typedef struct {
    const uint8_t *cur;
    const uint8_t *end;
    size_t need;
} mbedtls_ssl_chk_buf_ptr_args;

void mbedtls_ssl_set_chk_buf_ptr_fail_args(
    const uint8_t *cur, const uint8_t *end, size_t need);
void mbedtls_ssl_reset_chk_buf_ptr_fail_args(void);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_cmp_chk_buf_ptr_fail_args(mbedtls_ssl_chk_buf_ptr_args *args);

static inline int mbedtls_ssl_chk_buf_ptr(const uint8_t *cur,
                                          const uint8_t *end, size_t need)
{
    if ((cur > end) || (need > (size_t) (end - cur))) {
        mbedtls_ssl_set_chk_buf_ptr_fail_args(cur, end, need);
        return 1;
    }
    return 0;
}
#endif /* MBEDTLS_TEST_HOOKS */

/**
 * \brief        This macro checks if the remaining size in a buffer is
 *               greater or equal than a needed space. If it is not the case,
 *               it returns an SSL_BUFFER_TOO_SMALL error.
 *
 * \param cur    Pointer to the current position in the buffer.
 * \param end    Pointer to one past the end of the buffer.
 * \param need   Needed space in bytes.
 *
 */
#define MBEDTLS_SSL_CHK_BUF_PTR(cur, end, need)                        \
    do {                                                                 \
        if (mbedtls_ssl_chk_buf_ptr((cur), (end), (need)) != 0) \
        {                                                                \
            return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;                  \
        }                                                                \
    } while (0)

/**
 * \brief        This macro checks if the remaining length in an input buffer is
 *               greater or equal than a needed length. If it is not the case, it
 *               returns #MBEDTLS_ERR_SSL_DECODE_ERROR error and pends a
 *               #MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR alert message.
 *
 *               This is a function-like macro. It is guaranteed to evaluate each
 *               argument exactly once.
 *
 * \param cur    Pointer to the current position in the buffer.
 * \param end    Pointer to one past the end of the buffer.
 * \param need   Needed length in bytes.
 *
 */
#define MBEDTLS_SSL_CHK_BUF_READ_PTR(cur, end, need)                          \
    do {                                                                        \
        if (mbedtls_ssl_chk_buf_ptr((cur), (end), (need)) != 0)        \
        {                                                                       \
            MBEDTLS_SSL_DEBUG_MSG(1,                                           \
                                  ("missing input data in %s", __func__));  \
            MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,   \
                                         MBEDTLS_ERR_SSL_DECODE_ERROR);       \
            return MBEDTLS_ERR_SSL_DECODE_ERROR;                             \
        }                                                                       \
    } while (0)

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Return 1 if the transform uses an AEAD cipher, 0 otherwise.
 * Equivalently, return 0 if a separate MAC is used, 1 otherwise.
 */
static inline int mbedtls_ssl_transform_uses_aead(
    const mbedtls_ssl_transform *transform)
{
#if defined(MBEDTLS_SSL_SOME_SUITES_USE_MAC)
    return transform->maclen == 0 && transform->taglen != 0;
#else
    (void) transform;
    return 1;
#endif
}

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
/**
 * \brief Given an SSL context and its associated configuration, write the TLS
 *        1.2 specific extensions of the ClientHello message.
 *
 * \param[in]   ssl     SSL context
 * \param[in]   buf     Base address of the buffer where to write the extensions
 * \param[in]   end     End address of the buffer where to write the extensions
 * \param       uses_ec Whether one proposed ciphersuite uses an elliptic curve
 *                      (<> 0) or not ( 0 ).
 * \param[out]  out_len Length of the data written into the buffer \p buf
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls12_write_client_hello_exts(mbedtls_ssl_context *ssl,
                                              unsigned char *buf,
                                              const unsigned char *end,
                                              int uses_ec,
                                              size_t *out_len);
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && \
    defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)

/**
 * \brief Find the preferred hash for a given signature algorithm.
 *
 * \param[in]   ssl     SSL context
 * \param[in]   sig_alg A signature algorithm identifier as defined in the
 *                      TLS 1.2 SignatureAlgorithm enumeration.
 *
 * \return  The preferred hash algorithm for \p sig_alg. It is a hash algorithm
 *          identifier as defined in the TLS 1.2 HashAlgorithm enumeration.
 */
unsigned int mbedtls_ssl_tls12_get_preferred_hash_for_sig_alg(
    mbedtls_ssl_context *ssl,
    unsigned int sig_alg);

#endif /* MBEDTLS_SSL_PROTO_TLS1_2 &&
          MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

/**
 * \brief           Free referenced items in an SSL transform context and clear
 *                  memory
 *
 * \param transform SSL transform context
 */
void mbedtls_ssl_transform_free(mbedtls_ssl_transform *transform);

/**
 * \brief           Free referenced items in an SSL handshake context and clear
 *                  memory
 *
 * \param ssl       SSL context
 */
void mbedtls_ssl_handshake_free(mbedtls_ssl_context *ssl);

/* set inbound transform of ssl context */
void mbedtls_ssl_set_inbound_transform(mbedtls_ssl_context *ssl,
                                       mbedtls_ssl_transform *transform);

/* set outbound transform of ssl context */
void mbedtls_ssl_set_outbound_transform(mbedtls_ssl_context *ssl,
                                        mbedtls_ssl_transform *transform);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_handshake_client_step(mbedtls_ssl_context *ssl);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_handshake_server_step(mbedtls_ssl_context *ssl);
void mbedtls_ssl_handshake_wrapup(mbedtls_ssl_context *ssl);

static inline void mbedtls_ssl_handshake_set_state(mbedtls_ssl_context *ssl,
                                                   mbedtls_ssl_states state)
{
#if defined(MBEDTLS_DEBUG_C)
    MBEDTLS_SSL_DEBUG_MSG(3, ("handshake state: %d (%s) -> %d (%s)",
                              ssl->state, mbedtls_ssl_states_str((mbedtls_ssl_states) ssl->state),
                              (int) state, mbedtls_ssl_states_str(state)));
#endif
    ssl->state = (int) state;
}

static inline void mbedtls_ssl_handshake_increment_state(mbedtls_ssl_context *ssl)
{
    mbedtls_ssl_handshake_set_state(ssl, (mbedtls_ssl_states) (ssl->state + 1));
}

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_send_fatal_handshake_failure(mbedtls_ssl_context *ssl);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_reset_checksum(mbedtls_ssl_context *ssl);

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_derive_keys(mbedtls_ssl_context *ssl);
#endif /* MBEDTLS_SSL_PROTO_TLS1_2  */

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_handle_message_type(mbedtls_ssl_context *ssl);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_prepare_handshake_record(mbedtls_ssl_context *ssl);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_update_handshake_status(mbedtls_ssl_context *ssl);

/**
 * \brief       Update record layer
 *
 *              This function roughly separates the implementation
 *              of the logic of (D)TLS from the implementation
 *              of the secure transport.
 *
 * \param  ssl              The SSL context to use.
 * \param  update_hs_digest This indicates if the handshake digest
 *                          should be automatically updated in case
 *                          a handshake message is found.
 *
 * \return      0 or non-zero error code.
 *
 * \note        A clarification on what is called 'record layer' here
 *              is in order, as many sensible definitions are possible:
 *
 *              The record layer takes as input an untrusted underlying
 *              transport (stream or datagram) and transforms it into
 *              a serially multiplexed, secure transport, which
 *              conceptually provides the following:
 *
 *              (1) Three datagram based, content-agnostic transports
 *                  for handshake, alert and CCS messages.
 *              (2) One stream- or datagram-based transport
 *                  for application data.
 *              (3) Functionality for changing the underlying transform
 *                  securing the contents.
 *
 *              The interface to this functionality is given as follows:
 *
 *              a Updating
 *                [Currently implemented by mbedtls_ssl_read_record]
 *
 *                Check if and on which of the four 'ports' data is pending:
 *                Nothing, a controlling datagram of type (1), or application
 *                data (2). In any case data is present, internal buffers
 *                provide access to the data for the user to process it.
 *                Consumption of type (1) datagrams is done automatically
 *                on the next update, invalidating that the internal buffers
 *                for previous datagrams, while consumption of application
 *                data (2) is user-controlled.
 *
 *              b Reading of application data
 *                [Currently manual adaption of ssl->in_offt pointer]
 *
 *                As mentioned in the last paragraph, consumption of data
 *                is different from the automatic consumption of control
 *                datagrams (1) because application data is treated as a stream.
 *
 *              c Tracking availability of application data
 *                [Currently manually through decreasing ssl->in_msglen]
 *
 *                For efficiency and to retain datagram semantics for
 *                application data in case of DTLS, the record layer
 *                provides functionality for checking how much application
 *                data is still available in the internal buffer.
 *
 *              d Changing the transformation securing the communication.
 *
 *              Given an opaque implementation of the record layer in the
 *              above sense, it should be possible to implement the logic
 *              of (D)TLS on top of it without the need to know anything
 *              about the record layer's internals. This is done e.g.
 *              in all the handshake handling functions, and in the
 *              application data reading function mbedtls_ssl_read.
 *
 * \note        The above tries to give a conceptual picture of the
 *              record layer, but the current implementation deviates
 *              from it in some places. For example, our implementation of
 *              the update functionality through mbedtls_ssl_read_record
 *              discards datagrams depending on the current state, which
 *              wouldn't fall under the record layer's responsibility
 *              following the above definition.
 *
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_read_record(mbedtls_ssl_context *ssl,
                            unsigned update_hs_digest);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_fetch_input(mbedtls_ssl_context *ssl, size_t nb_want);

/*
 * Write handshake message header
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_start_handshake_msg(mbedtls_ssl_context *ssl, unsigned char hs_type,
                                    unsigned char **buf, size_t *buf_len);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_write_handshake_msg_ext(mbedtls_ssl_context *ssl,
                                        int update_checksum,
                                        int force_flush);
/*
 * Write handshake message tail
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_finish_handshake_msg(mbedtls_ssl_context *ssl,
                                     size_t buf_len, size_t msg_len);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_write_record(mbedtls_ssl_context *ssl, int force_flush);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_flush_output(mbedtls_ssl_context *ssl);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_parse_certificate(mbedtls_ssl_context *ssl);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_write_certificate(mbedtls_ssl_context *ssl);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_parse_change_cipher_spec(mbedtls_ssl_context *ssl);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_write_change_cipher_spec(mbedtls_ssl_context *ssl);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_parse_finished(mbedtls_ssl_context *ssl);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_write_finished(mbedtls_ssl_context *ssl);

void mbedtls_ssl_optimize_checksum(mbedtls_ssl_context *ssl,
                                   const mbedtls_ssl_ciphersuite_t *ciphersuite_info);

/*
 * Update checksum of handshake messages.
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_add_hs_msg_to_checksum(mbedtls_ssl_context *ssl,
                                       unsigned hs_type,
                                       unsigned char const *msg,
                                       size_t msg_len);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_add_hs_hdr_to_checksum(mbedtls_ssl_context *ssl,
                                       unsigned hs_type,
                                       size_t total_hs_len);

#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED)
#if defined(MBEDTLS_SSL_CLI_C) || defined(MBEDTLS_SSL_SRV_C)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_conf_has_static_psk(mbedtls_ssl_config const *conf);
#endif
/**
 * Get the first defined opaque PSK by order of precedence:
 * 1. handshake PSK set by \c mbedtls_ssl_set_hs_psk_opaque() in the PSK
 *    callback
 * 2. static PSK configured by \c mbedtls_ssl_conf_psk_opaque()
 * Return an opaque PSK
 */
static inline mbedtls_svc_key_id_t mbedtls_ssl_get_opaque_psk(
    const mbedtls_ssl_context *ssl)
{
    if (!mbedtls_svc_key_id_is_null(ssl->handshake->psk_opaque)) {
        return ssl->handshake->psk_opaque;
    }

    if (!mbedtls_svc_key_id_is_null(ssl->conf->psk_opaque)) {
        return ssl->conf->psk_opaque;
    }

    return MBEDTLS_SVC_KEY_ID_INIT;
}

#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED */

#if defined(MBEDTLS_PK_C)
unsigned char mbedtls_ssl_sig_from_pk(mbedtls_pk_context *pk);
unsigned char mbedtls_ssl_sig_from_pk_alg(mbedtls_pk_sigalg_t type);
mbedtls_pk_sigalg_t mbedtls_ssl_pk_sig_alg_from_sig(unsigned char sig);
#endif

mbedtls_md_type_t mbedtls_ssl_md_alg_from_hash(unsigned char hash);
unsigned char mbedtls_ssl_hash_from_md_alg(int md);

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_set_calc_verify_md(mbedtls_ssl_context *ssl, int md);
#endif

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_check_curve_tls_id(const mbedtls_ssl_context *ssl, uint16_t tls_id);

/**
 * \brief Return PSA EC info for the specified TLS ID.
 *
 * \param tls_id    The TLS ID to look for
 * \param type      If the TLD ID is supported, then proper \c psa_key_type_t
 *                  value is returned here. Can be NULL.
 * \param bits      If the TLD ID is supported, then proper bit size is returned
 *                  here. Can be NULL.
 * \return          PSA_SUCCESS if the TLS ID is supported,
 *                  PSA_ERROR_NOT_SUPPORTED otherwise
 *
 * \note            If either \c family or \c bits parameters are NULL, then
 *                  the corresponding value is not returned.
 *                  The function can be called with both parameters as NULL
 *                  simply to check if a specific TLS ID is supported.
 */
int mbedtls_ssl_get_psa_curve_info_from_tls_id(uint16_t tls_id,
                                               psa_key_type_t *type,
                                               size_t *bits);

/**
 * \brief Tell if a TLS group ID is supported or not.
 *
 * \param tls_id    The TLS ID to look for.
 * \return          1 if specified TLS ID is supported, 0 otherwise.
 */
int mbedtls_ssl_is_tls_id_supported(uint16_t tls_id);

/**
 * \brief Return TLS ID for the specified curve.
 *
 * \param family    The \c psa_ecc_family_t for the TLS ID to look for.
 * \param bits      The bit size for the TLS ID to look for.
 * \return          Proper TLS ID if the specified EC group is supported,
 *                  or 0 otherwise
 */
uint16_t mbedtls_ssl_get_tls_id_from_curve_info(psa_ecc_family_t family, size_t bits);

/**
 * \brief       Return the number of supported TLS group IDs + 1.
 *
 * \return      Number of supported TLS group IDs in \c tls_id_match_table + 1.
 *              In other words the returned value concides with the array length
 *              of \c tls_id_match_table.
 */
size_t mbedtls_ssl_get_supported_tls_id_count(void);

#if defined(MBEDTLS_DEBUG_C)
/**
 * \brief Return EC's name for the specified TLS ID.
 *
 * \param tls_id    The TLS ID to look for
 * \return          A pointer to a const string with the proper name. If TLS
 *                  ID is not supported, a NULL pointer is returned instead.
 */
const char *mbedtls_ssl_get_curve_name_from_tls_id(uint16_t tls_id);
#endif

#if defined(MBEDTLS_SSL_DTLS_SRTP)
static inline mbedtls_ssl_srtp_profile mbedtls_ssl_check_srtp_profile_value
    (const uint16_t srtp_profile_value)
{
    switch (srtp_profile_value) {
        case MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_80:
        case MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_32:
        case MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_80:
        case MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_32:
            return srtp_profile_value;
        default: break;
    }
    return MBEDTLS_TLS_SRTP_UNSET;
}
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
static inline mbedtls_pk_context *mbedtls_ssl_own_key(mbedtls_ssl_context *ssl)
{
    mbedtls_ssl_key_cert *key_cert;

    if (ssl->handshake != NULL && ssl->handshake->key_cert != NULL) {
        key_cert = ssl->handshake->key_cert;
    } else {
        key_cert = ssl->conf->key_cert;
    }

    return key_cert == NULL ? NULL : key_cert->key;
}

static inline mbedtls_x509_crt *mbedtls_ssl_own_cert(mbedtls_ssl_context *ssl)
{
    mbedtls_ssl_key_cert *key_cert;

    if (ssl->handshake != NULL && ssl->handshake->key_cert != NULL) {
        key_cert = ssl->handshake->key_cert;
    } else {
        key_cert = ssl->conf->key_cert;
    }

    return key_cert == NULL ? NULL : key_cert->cert;
}

/*
 * Verify a certificate.
 *
 * [in/out] ssl: misc. things read
 *               ssl->session_negotiate->verify_result updated
 * [in] authmode: one of MBEDTLS_SSL_VERIFY_{NONE,OPTIONAL,REQUIRED}
 * [in] chain: the certificate chain to verify (ie the peer's chain)
 * [in] ciphersuite_info: For TLS 1.2, this session's ciphersuite;
 *                        for TLS 1.3, may be left NULL.
 * [in] rs_ctx: restart context if restartable ECC is in use;
 *              leave NULL for no restartable behaviour.
 *
 * Return:
 * - 0 if the handshake should continue. Depending on the
 *   authmode it means:
 *   - REQUIRED: the certificate was found to be valid, trusted & acceptable.
 *     ssl->session_negotiate->verify_result is 0.
 *   - OPTIONAL: the certificate may or may not be acceptable, but
 *     ssl->session_negotiate->verify_result was updated with the result.
 *   - NONE: the certificate wasn't even checked.
 * - MBEDTLS_ERR_X509_CERT_VERIFY_FAILED or MBEDTLS_ERR_SSL_BAD_CERTIFICATE if
 *   the certificate was found to be invalid/untrusted/unacceptable and the
 *   handshake should be aborted (can only happen with REQUIRED).
 * - another error code if another error happened (out-of-memory, etc.)
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_verify_certificate(mbedtls_ssl_context *ssl,
                                   int authmode,
                                   mbedtls_x509_crt *chain,
                                   const mbedtls_ssl_ciphersuite_t *ciphersuite_info,
                                   void *rs_ctx);

/*
 * Check usage of a certificate wrt usage extensions:
 * keyUsage and extendedKeyUsage.
 * (Note: nSCertType is deprecated and not standard, we don't check it.)
 *
 * Note: if tls_version is 1.3, ciphersuite is ignored and can be NULL.
 *
 * Note: recv_endpoint is the receiver's endpoint.
 *
 * Return 0 if everything is OK, -1 if not.
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_check_cert_usage(const mbedtls_x509_crt *cert,
                                 const mbedtls_ssl_ciphersuite_t *ciphersuite,
                                 int recv_endpoint,
                                 mbedtls_ssl_protocol_version tls_version,
                                 uint32_t *flags);
#endif /* MBEDTLS_X509_CRT_PARSE_C */

void mbedtls_ssl_write_version(unsigned char version[2], int transport,
                               mbedtls_ssl_protocol_version tls_version);
uint16_t mbedtls_ssl_read_version(const unsigned char version[2],
                                  int transport);

static inline size_t mbedtls_ssl_in_hdr_len(const mbedtls_ssl_context *ssl)
{
#if !defined(MBEDTLS_SSL_PROTO_DTLS)
    ((void) ssl);
#endif

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        return 13;
    } else
#endif /* MBEDTLS_SSL_PROTO_DTLS */
    {
        return 5;
    }
}

static inline size_t mbedtls_ssl_out_hdr_len(const mbedtls_ssl_context *ssl)
{
    return (size_t) (ssl->out_iv - ssl->out_hdr);
}

static inline size_t mbedtls_ssl_hs_hdr_len(const mbedtls_ssl_context *ssl)
{
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        return 12;
    }
#else
    ((void) ssl);
#endif
    return 4;
}

#if defined(MBEDTLS_SSL_PROTO_DTLS)
void mbedtls_ssl_send_flight_completed(mbedtls_ssl_context *ssl);
void mbedtls_ssl_recv_flight_completed(mbedtls_ssl_context *ssl);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_resend(mbedtls_ssl_context *ssl);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_flight_transmit(mbedtls_ssl_context *ssl);
#endif

/* Visible for testing purposes only */
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_dtls_replay_check(mbedtls_ssl_context const *ssl);
void mbedtls_ssl_dtls_replay_update(mbedtls_ssl_context *ssl);
#endif

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_session_copy(mbedtls_ssl_session *dst,
                             const mbedtls_ssl_session *src);

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
/* The hash buffer must have at least MBEDTLS_MD_MAX_SIZE bytes of length. */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_get_key_exchange_md_tls1_2(mbedtls_ssl_context *ssl,
                                           unsigned char *hash, size_t *hashlen,
                                           unsigned char *data, size_t data_len,
                                           mbedtls_md_type_t md_alg);
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

#ifdef __cplusplus
}
#endif

void mbedtls_ssl_transform_init(mbedtls_ssl_transform *transform);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_encrypt_buf(mbedtls_ssl_context *ssl,
                            mbedtls_ssl_transform *transform,
                            mbedtls_record *rec);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_decrypt_buf(mbedtls_ssl_context const *ssl,
                            mbedtls_ssl_transform *transform,
                            mbedtls_record *rec);

/* Length of the "epoch" field in the record header */
static inline size_t mbedtls_ssl_ep_len(const mbedtls_ssl_context *ssl)
{
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        return 2;
    }
#else
    ((void) ssl);
#endif
    return 0;
}

#if defined(MBEDTLS_SSL_PROTO_DTLS)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_resend_hello_request(mbedtls_ssl_context *ssl);
#endif /* MBEDTLS_SSL_PROTO_DTLS */

void mbedtls_ssl_set_timer(mbedtls_ssl_context *ssl, uint32_t millisecs);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_check_timer(mbedtls_ssl_context *ssl);

void mbedtls_ssl_reset_in_pointers(mbedtls_ssl_context *ssl);
void mbedtls_ssl_update_in_pointers(mbedtls_ssl_context *ssl);
void mbedtls_ssl_reset_out_pointers(mbedtls_ssl_context *ssl);
void mbedtls_ssl_update_out_pointers(mbedtls_ssl_context *ssl,
                                     mbedtls_ssl_transform *transform);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_session_reset_int(mbedtls_ssl_context *ssl, int partial);
void mbedtls_ssl_session_reset_msg_layer(mbedtls_ssl_context *ssl,
                                         int partial);

/*
 * Send pending alert
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_handle_pending_alert(mbedtls_ssl_context *ssl);

/*
 * Set pending fatal alert flag.
 */
void mbedtls_ssl_pend_fatal_alert(mbedtls_ssl_context *ssl,
                                  unsigned char alert_type,
                                  int alert_reason);

/* Alias of mbedtls_ssl_pend_fatal_alert */
#define MBEDTLS_SSL_PEND_FATAL_ALERT(type, user_return_value)         \
    mbedtls_ssl_pend_fatal_alert(ssl, type, user_return_value)

#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
void mbedtls_ssl_dtls_replay_reset(mbedtls_ssl_context *ssl);
#endif

void mbedtls_ssl_handshake_wrapup_free_hs_transform(mbedtls_ssl_context *ssl);

#if defined(MBEDTLS_SSL_RENEGOTIATION)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_start_renegotiation(mbedtls_ssl_context *ssl);
#endif /* MBEDTLS_SSL_RENEGOTIATION */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
size_t mbedtls_ssl_get_current_mtu(const mbedtls_ssl_context *ssl);
void mbedtls_ssl_buffering_free(mbedtls_ssl_context *ssl);
void mbedtls_ssl_flight_free(mbedtls_ssl_flight_item *flight);
#endif /* MBEDTLS_SSL_PROTO_DTLS */

/**
 * ssl utils functions for checking configuration.
 */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
static inline int mbedtls_ssl_conf_is_tls13_only(const mbedtls_ssl_config *conf)
{
    return conf->min_tls_version == MBEDTLS_SSL_VERSION_TLS1_3 &&
           conf->max_tls_version == MBEDTLS_SSL_VERSION_TLS1_3;
}

#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
static inline int mbedtls_ssl_conf_is_tls12_only(const mbedtls_ssl_config *conf)
{
    return conf->min_tls_version == MBEDTLS_SSL_VERSION_TLS1_2 &&
           conf->max_tls_version == MBEDTLS_SSL_VERSION_TLS1_2;
}

#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

static inline int mbedtls_ssl_conf_is_tls13_enabled(const mbedtls_ssl_config *conf)
{
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    return conf->min_tls_version <= MBEDTLS_SSL_VERSION_TLS1_3 &&
           conf->max_tls_version >= MBEDTLS_SSL_VERSION_TLS1_3;
#else
    ((void) conf);
    return 0;
#endif
}

static inline int mbedtls_ssl_conf_is_tls12_enabled(const mbedtls_ssl_config *conf)
{
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    return conf->min_tls_version <= MBEDTLS_SSL_VERSION_TLS1_2 &&
           conf->max_tls_version >= MBEDTLS_SSL_VERSION_TLS1_2;
#else
    ((void) conf);
    return 0;
#endif
}

#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_SSL_PROTO_TLS1_3)
static inline int mbedtls_ssl_conf_is_hybrid_tls12_tls13(const mbedtls_ssl_config *conf)
{
    return conf->min_tls_version == MBEDTLS_SSL_VERSION_TLS1_2 &&
           conf->max_tls_version == MBEDTLS_SSL_VERSION_TLS1_3;
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 && MBEDTLS_SSL_PROTO_TLS1_3 */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
extern const uint8_t mbedtls_ssl_tls13_hello_retry_request_magic[
    MBEDTLS_SERVER_HELLO_RANDOM_LEN];
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_process_finished_message(mbedtls_ssl_context *ssl);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_write_finished_message(mbedtls_ssl_context *ssl);
void mbedtls_ssl_tls13_handshake_wrapup(mbedtls_ssl_context *ssl);

/**
 * \brief Given an SSL context and its associated configuration, write the TLS
 *        1.3 specific extensions of the ClientHello message.
 *
 * \param[in]   ssl     SSL context
 * \param[in]   buf     Base address of the buffer where to write the extensions
 * \param[in]   end     End address of the buffer where to write the extensions
 * \param[out]  out_len Length of the data written into the buffer \p buf
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_write_client_hello_exts(mbedtls_ssl_context *ssl,
                                              unsigned char *buf,
                                              unsigned char *end,
                                              size_t *out_len);

/**
 * \brief           TLS 1.3 client side state machine entry
 *
 * \param ssl       SSL context
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_handshake_client_step(mbedtls_ssl_context *ssl);

/**
 * \brief           TLS 1.3 server side state machine entry
 *
 * \param ssl       SSL context
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_handshake_server_step(mbedtls_ssl_context *ssl);


/*
 * Helper functions around key exchange modes.
 */
static inline int mbedtls_ssl_conf_tls13_is_kex_mode_enabled(mbedtls_ssl_context *ssl,
                                                             int kex_mode_mask)
{
    return (ssl->conf->tls13_kex_modes & kex_mode_mask) != 0;
}

static inline int mbedtls_ssl_conf_tls13_is_psk_enabled(mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_conf_tls13_is_kex_mode_enabled(ssl,
                                                      MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK);
}

static inline int mbedtls_ssl_conf_tls13_is_psk_ephemeral_enabled(mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_conf_tls13_is_kex_mode_enabled(ssl,
                                                      MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL);
}

static inline int mbedtls_ssl_conf_tls13_is_ephemeral_enabled(mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_conf_tls13_is_kex_mode_enabled(ssl,
                                                      MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL);
}

static inline int mbedtls_ssl_conf_tls13_is_some_ephemeral_enabled(mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_conf_tls13_is_kex_mode_enabled(ssl,
                                                      MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ALL);
}

static inline int mbedtls_ssl_conf_tls13_is_some_psk_enabled(mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_conf_tls13_is_kex_mode_enabled(ssl,
                                                      MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ALL);
}

#if defined(MBEDTLS_SSL_SRV_C) && \
    defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_PSK_ENABLED)
/**
 * Given a list of key exchange modes, check if at least one of them is
 * supported by peer.
 *
 * \param[in] ssl  SSL context
 * \param kex_modes_mask  Mask of the key exchange modes to check
 *
 * \return Non-zero if at least one of the key exchange modes is supported by
 *         the peer, otherwise \c 0.
 */
static inline int mbedtls_ssl_tls13_is_kex_mode_supported(mbedtls_ssl_context *ssl,
                                                          int kex_modes_mask)
{
    return (ssl->handshake->tls13_kex_modes & kex_modes_mask) != 0;
}

static inline int mbedtls_ssl_tls13_is_psk_supported(mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_tls13_is_kex_mode_supported(ssl,
                                                   MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK);
}

static inline int mbedtls_ssl_tls13_is_psk_ephemeral_supported(
    mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_tls13_is_kex_mode_supported(ssl,
                                                   MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL);
}

static inline int mbedtls_ssl_tls13_is_ephemeral_supported(mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_tls13_is_kex_mode_supported(ssl,
                                                   MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL);
}

static inline int mbedtls_ssl_tls13_is_some_ephemeral_supported(mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_tls13_is_kex_mode_supported(ssl,
                                                   MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ALL);
}

static inline int mbedtls_ssl_tls13_is_some_psk_supported(mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_tls13_is_kex_mode_supported(ssl,
                                                   MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ALL);
}
#endif /* MBEDTLS_SSL_SRV_C &&
          MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_PSK_ENABLED */

/*
 * Helper functions for extensions checking.
 */

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_check_received_extension(
    mbedtls_ssl_context *ssl,
    int hs_msg_type,
    unsigned int received_extension_type,
    uint32_t hs_msg_allowed_extensions_mask);

static inline void mbedtls_ssl_tls13_set_hs_sent_ext_mask(
    mbedtls_ssl_context *ssl, unsigned int extension_type)
{
    ssl->handshake->sent_extensions |=
        mbedtls_ssl_get_extension_mask(extension_type);
}

/*
 * Helper functions to check the selected key exchange mode.
 */
static inline int mbedtls_ssl_tls13_key_exchange_mode_check(
    mbedtls_ssl_context *ssl, int kex_mask)
{
    return (ssl->handshake->key_exchange_mode & kex_mask) != 0;
}

static inline int mbedtls_ssl_tls13_key_exchange_mode_with_psk(
    mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_tls13_key_exchange_mode_check(ssl,
                                                     MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ALL);
}

static inline int mbedtls_ssl_tls13_key_exchange_mode_with_ephemeral(
    mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_tls13_key_exchange_mode_check(ssl,
                                                     MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ALL);
}

/*
 * Fetch TLS 1.3 handshake message header
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_fetch_handshake_msg(mbedtls_ssl_context *ssl,
                                          unsigned hs_type,
                                          unsigned char **buf,
                                          size_t *buf_len);

/**
 * \brief Detect if a list of extensions contains a supported_versions
 *        extension or not.
 *
 * \param[in] ssl  SSL context
 * \param[in] buf  Address of the first byte of the extensions vector.
 * \param[in] end  End of the buffer containing the list of extensions.
 * \param[out] supported_versions_data  If the extension is present, address of
 *                                      its first byte of data, NULL otherwise.
 * \param[out] supported_versions_data_end  If the extension is present, address
 *                                          of the first byte immediately
 *                                          following the extension data, NULL
 *                                          otherwise.
 * \return 0  if the list of extensions does not contain a supported_versions
 *            extension.
 * \return 1  if the list of extensions contains a supported_versions
 *            extension.
 * \return    A negative value if an error occurred while parsing the
 *            extensions.
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_is_supported_versions_ext_present_in_exts(
    mbedtls_ssl_context *ssl,
    const unsigned char *buf, const unsigned char *end,
    const unsigned char **supported_versions_data,
    const unsigned char **supported_versions_data_end);

/*
 * Handler of TLS 1.3 server certificate message
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_process_certificate(mbedtls_ssl_context *ssl);

#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
/*
 * Handler of TLS 1.3 write Certificate message
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_write_certificate(mbedtls_ssl_context *ssl);

/*
 * Handler of TLS 1.3 write Certificate Verify message
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_write_certificate_verify(mbedtls_ssl_context *ssl);

#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED */

/*
 * Generic handler of Certificate Verify
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_process_certificate_verify(mbedtls_ssl_context *ssl);

/*
 * Write of dummy-CCS's for middlebox compatibility
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_write_change_cipher_spec(mbedtls_ssl_context *ssl);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_reset_transcript_for_hrr(mbedtls_ssl_context *ssl);

#if defined(PSA_WANT_ALG_ECDH) || defined(PSA_WANT_ALG_FFDH)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_generate_and_write_xxdh_key_exchange(
    mbedtls_ssl_context *ssl,
    uint16_t named_group,
    unsigned char *buf,
    unsigned char *end,
    size_t *out_len);
#endif /* PSA_WANT_ALG_ECDH || PSA_WANT_ALG_FFDH */

#if defined(MBEDTLS_SSL_EARLY_DATA)
int mbedtls_ssl_tls13_write_early_data_ext(mbedtls_ssl_context *ssl,
                                           int in_new_session_ticket,
                                           unsigned char *buf,
                                           const unsigned char *end,
                                           size_t *out_len);

int mbedtls_ssl_tls13_check_early_data_len(mbedtls_ssl_context *ssl,
                                           size_t early_data_len);
#endif /* MBEDTLS_SSL_EARLY_DATA */

#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
/*
 * Write Signature Algorithm extension
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_write_sig_alg_ext(mbedtls_ssl_context *ssl, unsigned char *buf,
                                  const unsigned char *end, size_t *out_len);
/*
 * Parse TLS Signature Algorithm extension
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_parse_sig_alg_ext(mbedtls_ssl_context *ssl,
                                  const unsigned char *buf,
                                  const unsigned char *end);
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */

/* Get handshake transcript */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_get_handshake_transcript(mbedtls_ssl_context *ssl,
                                         const mbedtls_md_type_t md,
                                         unsigned char *dst,
                                         size_t dst_len,
                                         size_t *olen);

/*
 * Helper functions for NamedGroup.
 */
static inline int mbedtls_ssl_tls12_named_group_is_ecdhe(uint16_t named_group)
{
    /*
     * RFC 8422 section 5.1.1
     */
    return named_group == MBEDTLS_SSL_IANA_TLS_GROUP_X25519    ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_BP256R1   ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_BP384R1   ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_BP512R1   ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_X448      ||
           /* Below deprecated curves should be removed with notice to users */
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_SECP256K1 ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1 ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1 ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_SECP521R1;
}

static inline int mbedtls_ssl_tls13_named_group_is_ecdhe(uint16_t named_group)
{
    return named_group == MBEDTLS_SSL_IANA_TLS_GROUP_X25519    ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1 ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1 ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_SECP521R1 ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_X448;
}

static inline int mbedtls_ssl_tls13_named_group_is_ffdh(uint16_t named_group)
{
    return named_group >= MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE2048 &&
           named_group <= MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE8192;
}

static inline int mbedtls_ssl_named_group_is_offered(
    const mbedtls_ssl_context *ssl, uint16_t named_group)
{
    const uint16_t *group_list = ssl->conf->group_list;

    if (group_list == NULL) {
        return 0;
    }

    for (; *group_list != 0; group_list++) {
        if (*group_list == named_group) {
            return 1;
        }
    }

    return 0;
}

static inline int mbedtls_ssl_named_group_is_supported(uint16_t named_group)
{
#if defined(PSA_WANT_ALG_ECDH)
    if (mbedtls_ssl_tls13_named_group_is_ecdhe(named_group)) {
        if (mbedtls_ssl_is_tls_id_supported(named_group)) {
            return 1;
        }
    }
#endif
#if defined(PSA_WANT_ALG_FFDH)
    if (mbedtls_ssl_tls13_named_group_is_ffdh(named_group)) {
        return 1;
    }
#endif
#if !defined(PSA_WANT_ALG_ECDH) && !defined(PSA_WANT_ALG_FFDH)
    (void) named_group;
#endif
    return 0;
}

/*
 * Return supported signature algorithms.
 */
static inline const void *mbedtls_ssl_get_sig_algs(
    const mbedtls_ssl_context *ssl)
{
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)

    return ssl->conf->sig_algs;

#else /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */

    ((void) ssl);
    return NULL;
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */
}

#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
static inline int mbedtls_ssl_sig_alg_is_received(const mbedtls_ssl_context *ssl,
                                                  uint16_t own_sig_alg)
{
    const uint16_t *sig_alg = ssl->handshake->received_sig_algs;
    if (sig_alg == NULL) {
        return 0;
    }

    for (; *sig_alg != MBEDTLS_TLS_SIG_NONE; sig_alg++) {
        if (*sig_alg == own_sig_alg) {
            return 1;
        }
    }
    return 0;
}

static inline int mbedtls_ssl_tls13_sig_alg_for_cert_verify_is_supported(
    const uint16_t sig_alg)
{
    switch (sig_alg) {
#if defined(PSA_HAVE_ALG_SOME_ECDSA)
#if defined(PSA_WANT_ALG_SHA_256) && defined(PSA_WANT_ECC_SECP_R1_256)
        case MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256:
            break;
#endif /* PSA_WANT_ALG_SHA_256 && PSA_WANT_ECC_SECP_R1_256 */
#if defined(PSA_WANT_ALG_SHA_384) && defined(PSA_WANT_ECC_SECP_R1_384)
        case MBEDTLS_TLS1_3_SIG_ECDSA_SECP384R1_SHA384:
            break;
#endif /* PSA_WANT_ALG_SHA_384 && PSA_WANT_ECC_SECP_R1_384 */
#if defined(PSA_WANT_ALG_SHA_512) && defined(PSA_WANT_ECC_SECP_R1_521)
        case MBEDTLS_TLS1_3_SIG_ECDSA_SECP521R1_SHA512:
            break;
#endif /* PSA_WANT_ALG_SHA_512 && PSA_WANT_ECC_SECP_R1_521 */
#endif /* PSA_HAVE_ALG_SOME_ECDSA */

#if defined(PSA_WANT_ALG_RSA_PSS)
#if defined(PSA_WANT_ALG_SHA_256)
        case MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA256:
            break;
#endif /* PSA_WANT_ALG_SHA_256  */
#if defined(PSA_WANT_ALG_SHA_384)
        case MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA384:
            break;
#endif /* PSA_WANT_ALG_SHA_384 */
#if defined(PSA_WANT_ALG_SHA_512)
        case MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA512:
            break;
#endif /* PSA_WANT_ALG_SHA_512 */
#endif /* PSA_WANT_ALG_RSA_PSS */
        default:
            return 0;
    }
    return 1;

}

static inline int mbedtls_ssl_tls13_sig_alg_is_supported(
    const uint16_t sig_alg)
{
    switch (sig_alg) {
#if defined(PSA_WANT_ALG_RSA_PKCS1V15_SIGN)
#if defined(PSA_WANT_ALG_SHA_256)
        case MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA256:
            break;
#endif /* PSA_WANT_ALG_SHA_256 */
#if defined(PSA_WANT_ALG_SHA_384)
        case MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA384:
            break;
#endif /* PSA_WANT_ALG_SHA_384 */
#if defined(PSA_WANT_ALG_SHA_512)
        case MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA512:
            break;
#endif /* PSA_WANT_ALG_SHA_512 */
#endif /* PSA_WANT_ALG_RSA_PKCS1V15_SIGN */
        default:
            return mbedtls_ssl_tls13_sig_alg_for_cert_verify_is_supported(
                sig_alg);
    }
    return 1;
}

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_check_sig_alg_cert_key_match(uint16_t sig_alg,
                                                   mbedtls_pk_context *key);
#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED */

#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
static inline int mbedtls_ssl_sig_alg_is_offered(const mbedtls_ssl_context *ssl,
                                                 uint16_t proposed_sig_alg)
{
    const uint16_t *sig_alg = mbedtls_ssl_get_sig_algs(ssl);
    if (sig_alg == NULL) {
        return 0;
    }

    for (; *sig_alg != MBEDTLS_TLS_SIG_NONE; sig_alg++) {
        if (*sig_alg == proposed_sig_alg) {
            return 1;
        }
    }
    return 0;
}

static inline int mbedtls_ssl_get_pk_sigalg_and_md_alg_from_sig_alg(
    uint16_t sig_alg, mbedtls_pk_sigalg_t *pk_type, mbedtls_md_type_t *md_alg)
{
    *pk_type = mbedtls_ssl_pk_sig_alg_from_sig(sig_alg & 0xff);
    *md_alg = mbedtls_ssl_md_alg_from_hash((sig_alg >> 8) & 0xff);

    if (*pk_type != MBEDTLS_PK_SIGALG_NONE && *md_alg != MBEDTLS_MD_NONE) {
        return 0;
    }

    switch (sig_alg) {
#if defined(PSA_WANT_ALG_RSA_PSS)
#if defined(PSA_WANT_ALG_SHA_256)
        case MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA256:
            *md_alg = MBEDTLS_MD_SHA256;
            *pk_type = MBEDTLS_PK_SIGALG_RSA_PSS;
            break;
#endif /* PSA_WANT_ALG_SHA_256  */
#if defined(PSA_WANT_ALG_SHA_384)
        case MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA384:
            *md_alg = MBEDTLS_MD_SHA384;
            *pk_type = MBEDTLS_PK_SIGALG_RSA_PSS;
            break;
#endif /* PSA_WANT_ALG_SHA_384 */
#if defined(PSA_WANT_ALG_SHA_512)
        case MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA512:
            *md_alg = MBEDTLS_MD_SHA512;
            *pk_type = MBEDTLS_PK_SIGALG_RSA_PSS;
            break;
#endif /* PSA_WANT_ALG_SHA_512 */
#endif /* PSA_WANT_ALG_RSA_PSS */
        default:
            return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    }
    return 0;
}

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
static inline int mbedtls_ssl_tls12_sig_alg_is_supported(
    const uint16_t sig_alg)
{
    /* High byte is hash */
    unsigned char hash = MBEDTLS_BYTE_1(sig_alg);
    unsigned char sig = MBEDTLS_BYTE_0(sig_alg);

    switch (hash) {
#if defined(PSA_WANT_ALG_MD5)
        case MBEDTLS_SSL_HASH_MD5:
            break;
#endif

#if defined(PSA_WANT_ALG_SHA_1)
        case MBEDTLS_SSL_HASH_SHA1:
            break;
#endif

#if defined(PSA_WANT_ALG_SHA_224)
        case MBEDTLS_SSL_HASH_SHA224:
            break;
#endif

#if defined(PSA_WANT_ALG_SHA_256)
        case MBEDTLS_SSL_HASH_SHA256:
            break;
#endif

#if defined(PSA_WANT_ALG_SHA_384)
        case MBEDTLS_SSL_HASH_SHA384:
            break;
#endif

#if defined(PSA_WANT_ALG_SHA_512)
        case MBEDTLS_SSL_HASH_SHA512:
            break;
#endif

        default:
            return 0;
    }

    switch (sig) {
#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC)
        case MBEDTLS_SSL_SIG_RSA:
            break;
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED)
        case MBEDTLS_SSL_SIG_ECDSA:
            break;
#endif

        default:
            return 0;
    }

    return 1;
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

static inline int mbedtls_ssl_sig_alg_is_supported(
    const mbedtls_ssl_context *ssl,
    const uint16_t sig_alg)
{

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if (ssl->tls_version == MBEDTLS_SSL_VERSION_TLS1_2) {
        return mbedtls_ssl_tls12_sig_alg_is_supported(sig_alg);
    }
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
    if (ssl->tls_version == MBEDTLS_SSL_VERSION_TLS1_3) {
        return mbedtls_ssl_tls13_sig_alg_is_supported(sig_alg);
    }
#endif
    ((void) ssl);
    ((void) sig_alg);
    return 0;
}
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */

/* Corresponding PSA algorithm for MBEDTLS_CIPHER_NULL.
 * Same value is used for PSA_ALG_CATEGORY_CIPHER, hence it is
 * guaranteed to not be a valid PSA algorithm identifier.
 */
#define MBEDTLS_SSL_NULL_CIPHER 0x04000000

/**
 * \brief       Translate mbedtls cipher type/taglen pair to psa:
 *              algorithm, key type and key size.
 *
 * \param  mbedtls_cipher_type [in] given mbedtls cipher type
 * \param  taglen              [in] given tag length
 *                                  0 - default tag length
 * \param  alg                 [out] corresponding PSA alg
 *                                   There is no corresponding PSA
 *                                   alg for MBEDTLS_CIPHER_NULL, so
 *                                   in this case MBEDTLS_SSL_NULL_CIPHER
 *                                   is returned via this parameter
 * \param  key_type            [out] corresponding PSA key type
 * \param  key_size            [out] corresponding PSA key size
 *
 * \return                     PSA_SUCCESS on success or PSA_ERROR_NOT_SUPPORTED if
 *                             conversion is not supported.
 */
psa_status_t mbedtls_ssl_cipher_to_psa(mbedtls_cipher_type_t mbedtls_cipher_type,
                                       size_t taglen,
                                       psa_algorithm_t *alg,
                                       psa_key_type_t *key_type,
                                       size_t *key_size);

#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)

typedef enum {
    MBEDTLS_ECJPAKE_ROUND_ONE,
    MBEDTLS_ECJPAKE_ROUND_TWO
} mbedtls_ecjpake_rounds_t;

/**
 * \brief       Parse the provided input buffer for getting the first round
 *              of key exchange. This code is common between server and client
 *
 * \param  pake_ctx [in] the PAKE's operation/context structure
 * \param  buf      [in] input buffer to parse
 * \param  len      [in] length of the input buffer
 * \param  round    [in] either MBEDTLS_ECJPAKE_ROUND_ONE or
 *                       MBEDTLS_ECJPAKE_ROUND_TWO
 *
 * \return               0 on success or a negative error code in case of failure
 */
int mbedtls_psa_ecjpake_read_round(
    psa_pake_operation_t *pake_ctx,
    const unsigned char *buf,
    size_t len, mbedtls_ecjpake_rounds_t round);

/**
 * \brief       Write the first round of key exchange into the provided output
 *              buffer. This code is common between server and client
 *
 * \param  pake_ctx [in] the PAKE's operation/context structure
 * \param  buf      [out] the output buffer in which data will be written to
 * \param  len      [in] length of the output buffer
 * \param  olen     [out] the length of the data really written on the buffer
 * \param  round    [in] either MBEDTLS_ECJPAKE_ROUND_ONE or
 *                       MBEDTLS_ECJPAKE_ROUND_TWO
 *
 * \return               0 on success or a negative error code in case of failure
 */
int mbedtls_psa_ecjpake_write_round(
    psa_pake_operation_t *pake_ctx,
    unsigned char *buf,
    size_t len, size_t *olen,
    mbedtls_ecjpake_rounds_t round);

#endif /* MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

/**
 * \brief       TLS record protection modes
 */
typedef enum {
    MBEDTLS_SSL_MODE_STREAM = 0,
    MBEDTLS_SSL_MODE_CBC,
    MBEDTLS_SSL_MODE_CBC_ETM,
    MBEDTLS_SSL_MODE_AEAD
} mbedtls_ssl_mode_t;

mbedtls_ssl_mode_t mbedtls_ssl_get_mode_from_transform(
    const mbedtls_ssl_transform *transform);

#if defined(MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
mbedtls_ssl_mode_t mbedtls_ssl_get_mode_from_ciphersuite(
    int encrypt_then_mac,
    const mbedtls_ssl_ciphersuite_t *suite);
#else
mbedtls_ssl_mode_t mbedtls_ssl_get_mode_from_ciphersuite(
    const mbedtls_ssl_ciphersuite_t *suite);
#endif /* MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM */

#if defined(PSA_WANT_ALG_ECDH) || defined(PSA_WANT_ALG_FFDH)

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_read_public_xxdhe_share(mbedtls_ssl_context *ssl,
                                              const unsigned char *buf,
                                              size_t buf_len);

#endif /* PSA_WANT_ALG_ECDH || PSA_WANT_ALG_FFDH */

static inline int mbedtls_ssl_tls13_cipher_suite_is_offered(
    mbedtls_ssl_context *ssl, int cipher_suite)
{
    const int *ciphersuite_list = ssl->conf->ciphersuite_list;

    /* Check whether we have offered this ciphersuite */
    for (size_t i = 0; ciphersuite_list[i] != 0; i++) {
        if (ciphersuite_list[i] == cipher_suite) {
            return 1;
        }
    }
    return 0;
}

/**
 * \brief Validate cipher suite against config in SSL context.
 *
 * \param ssl              SSL context
 * \param suite_info       Cipher suite to validate
 * \param min_tls_version  Minimal TLS version to accept a cipher suite
 * \param max_tls_version  Maximal TLS version to accept a cipher suite
 *
 * \return 0 if valid, negative value otherwise.
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_validate_ciphersuite(
    const mbedtls_ssl_context *ssl,
    const mbedtls_ssl_ciphersuite_t *suite_info,
    mbedtls_ssl_protocol_version min_tls_version,
    mbedtls_ssl_protocol_version max_tls_version);

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_parse_server_name_ext(mbedtls_ssl_context *ssl,
                                      const unsigned char *buf,
                                      const unsigned char *end);
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(MBEDTLS_SSL_RECORD_SIZE_LIMIT)
#define MBEDTLS_SSL_RECORD_SIZE_LIMIT_EXTENSION_DATA_LENGTH (2)
#define MBEDTLS_SSL_RECORD_SIZE_LIMIT_MIN (64)      /* As defined in RFC 8449 */

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_parse_record_size_limit_ext(mbedtls_ssl_context *ssl,
                                                  const unsigned char *buf,
                                                  const unsigned char *end);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_write_record_size_limit_ext(mbedtls_ssl_context *ssl,
                                                  unsigned char *buf,
                                                  const unsigned char *end,
                                                  size_t *out_len);
#endif /* MBEDTLS_SSL_RECORD_SIZE_LIMIT */

#if defined(MBEDTLS_SSL_ALPN)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_parse_alpn_ext(mbedtls_ssl_context *ssl,
                               const unsigned char *buf,
                               const unsigned char *end);


MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_write_alpn_ext(mbedtls_ssl_context *ssl,
                               unsigned char *buf,
                               unsigned char *end,
                               size_t *out_len);
#endif /* MBEDTLS_SSL_ALPN */

#if defined(MBEDTLS_TEST_HOOKS)
int mbedtls_ssl_check_dtls_clihlo_cookie(
    mbedtls_ssl_context *ssl,
    const unsigned char *cli_id, size_t cli_id_len,
    const unsigned char *in, size_t in_len,
    unsigned char *obuf, size_t buf_len, size_t *olen);
#endif

#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_PSK_ENABLED)
/**
 * \brief Given an SSL context and its associated configuration, write the TLS
 *        1.3 specific Pre-Shared key extension.
 *
 * \param[in]   ssl     SSL context
 * \param[in]   buf     Base address of the buffer where to write the extension
 * \param[in]   end     End address of the buffer where to write the extension
 * \param[out]  out_len Length in bytes of the Pre-Shared key extension: data
 *                      written into the buffer \p buf by this function plus
 *                      the length of the binders to be written.
 * \param[out]  binders_len Length of the binders to be written at the end of
 *                          the extension.
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_write_identities_of_pre_shared_key_ext(
    mbedtls_ssl_context *ssl,
    unsigned char *buf, unsigned char *end,
    size_t *out_len, size_t *binders_len);

/**
 * \brief Given an SSL context and its associated configuration, write the TLS
 *        1.3 specific Pre-Shared key extension binders at the end of the
 *        ClientHello.
 *
 * \param[in]   ssl     SSL context
 * \param[in]   buf     Base address of the buffer where to write the binders
 * \param[in]   end     End address of the buffer where to write the binders
 */
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_write_binders_of_pre_shared_key_ext(
    mbedtls_ssl_context *ssl,
    unsigned char *buf, unsigned char *end);
#endif /* MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_PSK_ENABLED */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && \
    defined(MBEDTLS_SSL_SESSION_TICKETS) && \
    defined(MBEDTLS_SSL_SERVER_NAME_INDICATION) && \
    defined(MBEDTLS_SSL_CLI_C)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_session_set_hostname(mbedtls_ssl_session *session,
                                     const char *hostname);
#endif

#if defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_EARLY_DATA) && \
    defined(MBEDTLS_SSL_ALPN)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_session_set_ticket_alpn(mbedtls_ssl_session *session,
                                        const char *alpn);
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_SSL_SESSION_TICKETS)

#define MBEDTLS_SSL_TLS1_3_MAX_ALLOWED_TICKET_LIFETIME (604800)

static inline unsigned int mbedtls_ssl_tls13_session_get_ticket_flags(
    mbedtls_ssl_session *session, unsigned int flags)
{
    return session->ticket_flags &
           (flags & MBEDTLS_SSL_TLS1_3_TICKET_FLAGS_MASK);
}

/**
 * Check if at least one of the given flags is set in
 * the session ticket. See the definition of
 * `MBEDTLS_SSL_TLS1_3_TICKET_FLAGS_MASK` to get all
 * permitted flags.
 */
static inline int mbedtls_ssl_tls13_session_ticket_has_flags(
    mbedtls_ssl_session *session, unsigned int flags)
{
    return mbedtls_ssl_tls13_session_get_ticket_flags(session, flags) != 0;
}

static inline int mbedtls_ssl_tls13_session_ticket_allow_psk(
    mbedtls_ssl_session *session)
{
    return mbedtls_ssl_tls13_session_ticket_has_flags(
        session, MBEDTLS_SSL_TLS1_3_TICKET_ALLOW_PSK_RESUMPTION);
}

static inline int mbedtls_ssl_tls13_session_ticket_allow_psk_ephemeral(
    mbedtls_ssl_session *session)
{
    return mbedtls_ssl_tls13_session_ticket_has_flags(
        session, MBEDTLS_SSL_TLS1_3_TICKET_ALLOW_PSK_EPHEMERAL_RESUMPTION);
}

static inline unsigned int mbedtls_ssl_tls13_session_ticket_allow_early_data(
    mbedtls_ssl_session *session)
{
    return mbedtls_ssl_tls13_session_ticket_has_flags(
        session, MBEDTLS_SSL_TLS1_3_TICKET_ALLOW_EARLY_DATA);
}

static inline void mbedtls_ssl_tls13_session_set_ticket_flags(
    mbedtls_ssl_session *session, unsigned int flags)
{
    session->ticket_flags |= (flags & MBEDTLS_SSL_TLS1_3_TICKET_FLAGS_MASK);
}

static inline void mbedtls_ssl_tls13_session_clear_ticket_flags(
    mbedtls_ssl_session *session, unsigned int flags)
{
    session->ticket_flags &= ~(flags & MBEDTLS_SSL_TLS1_3_TICKET_FLAGS_MASK);
}
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 && MBEDTLS_SSL_SESSION_TICKETS */

#if defined(MBEDTLS_SSL_CLI_C) && defined(MBEDTLS_SSL_PROTO_TLS1_3)
int mbedtls_ssl_tls13_finalize_client_hello(mbedtls_ssl_context *ssl);
#endif

#if defined(MBEDTLS_TEST_HOOKS) && defined(MBEDTLS_SSL_SOME_SUITES_USE_MAC)

/** Compute the HMAC of variable-length data with constant flow.
 *
 * This function computes the HMAC of the concatenation of \p add_data and \p
 * data, and does with a code flow and memory access pattern that does not
 * depend on \p data_len_secret, but only on \p min_data_len and \p
 * max_data_len. In particular, this function always reads exactly \p
 * max_data_len bytes from \p data.
 *
 * \param key               The HMAC key.
 * \param mac_alg           The hash algorithm.
 *                          Must be one of SHA-384, SHA-256, SHA-1 or MD-5.
 * \param add_data          The first part of the message whose HMAC is being
 *                          calculated. This must point to a readable buffer
 *                          of \p add_data_len bytes.
 * \param add_data_len      The length of \p add_data in bytes.
 * \param data              The buffer containing the second part of the
 *                          message. This must point to a readable buffer
 *                          of \p max_data_len bytes.
 * \param data_len_secret   The length of the data to process in \p data.
 *                          This must be no less than \p min_data_len and no
 *                          greater than \p max_data_len.
 * \param min_data_len      The minimal length of the second part of the
 *                          message, read from \p data.
 * \param max_data_len      The maximal length of the second part of the
 *                          message, read from \p data.
 * \param output            The HMAC will be written here. This must point to
 *                          a writable buffer of sufficient size to hold the
 *                          HMAC value.
 *
 * \retval 0 on success.
 * \retval #MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED
 *         The hardware accelerator failed.
 */
int mbedtls_ct_hmac(mbedtls_svc_key_id_t key,
                    psa_algorithm_t mac_alg,
                    const unsigned char *add_data,
                    size_t add_data_len,
                    const unsigned char *data,
                    size_t data_len_secret,
                    size_t min_data_len,
                    size_t max_data_len,
                    unsigned char *output);
#endif /* MBEDTLS_TEST_HOOKS && defined(MBEDTLS_SSL_SOME_SUITES_USE_MAC) */

#endif /* ssl_misc.h */
