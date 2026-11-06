/**
 * \file ssl_types.h
 *
 * \brief Internal types shared by the SSL modules
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_SSL_TYPES_H
#define MBEDTLS_SSL_TYPES_H

#include "mbedtls/ssl.h"

/*
 * DTLS retransmission states, see RFC 6347 4.2.4
 *
 * The SENDING state is merged in PREPARING for initial sends,
 * but is distinct for resends.
 *
 * Note: initial state is wrong for server, but is not used anyway.
 */
#define MBEDTLS_SSL_RETRANS_PREPARING       0
#define MBEDTLS_SSL_RETRANS_SENDING         1
#define MBEDTLS_SSL_RETRANS_WAITING         2
#define MBEDTLS_SSL_RETRANS_FINISHED        3

/*
 * Allow extra bytes for record, authentication and encryption overhead:
 * counter (8) + header (5) + IV(16) + MAC (16-48) + padding (0-256).
 */

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)

/* This macro determines whether CBC is supported. */
#if defined(PSA_WANT_ALG_CBC_NO_PADDING)      &&                                  \
    (defined(PSA_WANT_KEY_TYPE_AES)     ||                                  \
    defined(PSA_WANT_KEY_TYPE_CAMELLIA) ||                                  \
    defined(PSA_WANT_KEY_TYPE_ARIA))
#define MBEDTLS_SSL_SOME_SUITES_USE_CBC
#endif

/* This macro determines whether a ciphersuite using a
 * stream cipher can be used. */
#if defined(MBEDTLS_SSL_NULL_CIPHERSUITES)
#define MBEDTLS_SSL_SOME_SUITES_USE_STREAM
#endif

/* This macro determines whether the CBC construct used in TLS 1.2 is supported. */
#if defined(MBEDTLS_SSL_SOME_SUITES_USE_CBC) && \
    defined(MBEDTLS_SSL_PROTO_TLS1_2)
#define MBEDTLS_SSL_SOME_SUITES_USE_TLS_CBC
#endif

#if defined(MBEDTLS_SSL_SOME_SUITES_USE_STREAM) || \
    defined(MBEDTLS_SSL_SOME_SUITES_USE_CBC)
#define MBEDTLS_SSL_SOME_SUITES_USE_MAC
#endif

/* This macro determines whether a ciphersuite uses Encrypt-then-MAC with CBC */
#if defined(MBEDTLS_SSL_SOME_SUITES_USE_CBC) && \
    defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
#define MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM
#endif

#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

#if defined(MBEDTLS_SSL_SOME_SUITES_USE_MAC)
/* Ciphersuites using HMAC */
#if defined(PSA_WANT_ALG_SHA_384)
#define MBEDTLS_SSL_MAC_ADD                 48  /* SHA-384 used for HMAC */
#elif defined(PSA_WANT_ALG_SHA_256)
#define MBEDTLS_SSL_MAC_ADD                 32  /* SHA-256 used for HMAC */
#else
#define MBEDTLS_SSL_MAC_ADD                 20  /* SHA-1   used for HMAC */
#endif
#else /* MBEDTLS_SSL_SOME_SUITES_USE_MAC */
/* AEAD ciphersuites: GCM and CCM use a 128 bits tag */
#define MBEDTLS_SSL_MAC_ADD                 16
#endif

#if defined(PSA_WANT_ALG_CBC_NO_PADDING)
#define MBEDTLS_SSL_PADDING_ADD            256
#else
#define MBEDTLS_SSL_PADDING_ADD              0
#endif

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
#define MBEDTLS_SSL_MAX_CID_EXPANSION      MBEDTLS_SSL_CID_TLS1_3_PADDING_GRANULARITY
#else
#define MBEDTLS_SSL_MAX_CID_EXPANSION        0
#endif

#define MBEDTLS_SSL_PAYLOAD_OVERHEAD (MBEDTLS_MAX_IV_LENGTH +          \
                                      MBEDTLS_SSL_MAC_ADD +            \
                                      MBEDTLS_SSL_PADDING_ADD +        \
                                      MBEDTLS_SSL_MAX_CID_EXPANSION    \
                                      )

#define MBEDTLS_SSL_IN_PAYLOAD_LEN (MBEDTLS_SSL_PAYLOAD_OVERHEAD + \
                                    (MBEDTLS_SSL_IN_CONTENT_LEN))

#define MBEDTLS_SSL_OUT_PAYLOAD_LEN (MBEDTLS_SSL_PAYLOAD_OVERHEAD + \
                                     (MBEDTLS_SSL_OUT_CONTENT_LEN))

/* The maximum number of buffered handshake messages. */
#define MBEDTLS_SSL_MAX_BUFFERED_HS 4

/* Maximum length we can advertise as our max content length for
   RFC 6066 max_fragment_length extension negotiation purposes
   (the lesser of both sizes, if they are unequal.)
 */
#define MBEDTLS_TLS_EXT_ADV_CONTENT_LEN (                            \
        (MBEDTLS_SSL_IN_CONTENT_LEN > MBEDTLS_SSL_OUT_CONTENT_LEN)   \
        ? (MBEDTLS_SSL_OUT_CONTENT_LEN)                            \
        : (MBEDTLS_SSL_IN_CONTENT_LEN)                             \
        )

/* Maximum size in bytes of list in signature algorithms ext., RFC 5246/8446 */
#define MBEDTLS_SSL_MAX_SIG_ALG_LIST_LEN       65534

/* Minimum size in bytes of list in signature algorithms ext., RFC 5246/8446 */
#define MBEDTLS_SSL_MIN_SIG_ALG_LIST_LEN       2

/* Maximum size in bytes of list in supported elliptic curve ext., RFC 4492 */
#define MBEDTLS_SSL_MAX_CURVE_LIST_LEN         65535

#define MBEDTLS_RECEIVED_SIG_ALGS_SIZE         20

#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)

#define MBEDTLS_TLS_SIG_NONE MBEDTLS_TLS1_3_SIG_NONE

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#define MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(sig, hash) ((hash << 8) | sig)
#define MBEDTLS_SSL_TLS12_SIG_ALG_FROM_SIG_AND_HASH_ALG(alg) (alg & 0xFF)
#define MBEDTLS_SSL_TLS12_HASH_ALG_FROM_SIG_AND_HASH_ALG(alg) (alg >> 8)
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED */

/*
 * Check that we obey the standard's message size bounds
 */

#if MBEDTLS_SSL_IN_CONTENT_LEN > 16384
#error "Bad configuration - incoming record content too large."
#endif

#if MBEDTLS_SSL_OUT_CONTENT_LEN > 16384
#error "Bad configuration - outgoing record content too large."
#endif

#if MBEDTLS_SSL_IN_PAYLOAD_LEN > MBEDTLS_SSL_IN_CONTENT_LEN + 2048
#error "Bad configuration - incoming protected record payload too large."
#endif

#if MBEDTLS_SSL_OUT_PAYLOAD_LEN > MBEDTLS_SSL_OUT_CONTENT_LEN + 2048
#error "Bad configuration - outgoing protected record payload too large."
#endif

/* Calculate buffer sizes */

/* Note: Even though the TLS record header is only 5 bytes
   long, we're internally using 8 bytes to store the
   implicit sequence number. */
#define MBEDTLS_SSL_HEADER_LEN 13

#if !defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
#define MBEDTLS_SSL_IN_BUFFER_LEN  \
    ((MBEDTLS_SSL_HEADER_LEN) + (MBEDTLS_SSL_IN_PAYLOAD_LEN))
#else
#define MBEDTLS_SSL_IN_BUFFER_LEN  \
    ((MBEDTLS_SSL_HEADER_LEN) + (MBEDTLS_SSL_IN_PAYLOAD_LEN) \
     + (MBEDTLS_SSL_CID_IN_LEN_MAX))
#endif

#if !defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
#define MBEDTLS_SSL_OUT_BUFFER_LEN  \
    ((MBEDTLS_SSL_HEADER_LEN) + (MBEDTLS_SSL_OUT_PAYLOAD_LEN))
#else
#define MBEDTLS_SSL_OUT_BUFFER_LEN                               \
    ((MBEDTLS_SSL_HEADER_LEN) + (MBEDTLS_SSL_OUT_PAYLOAD_LEN)    \
     + (MBEDTLS_SSL_CID_OUT_LEN_MAX))
#endif

#define MBEDTLS_CLIENT_HELLO_RANDOM_LEN 32
#define MBEDTLS_SERVER_HELLO_RANDOM_LEN 32

/* Shorthand for restartable ECC */
#if defined(MBEDTLS_ECP_RESTARTABLE) && \
    defined(MBEDTLS_SSL_CLI_C) && \
    defined(MBEDTLS_SSL_PROTO_TLS1_2) && \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
#define MBEDTLS_SSL_ECP_RESTARTABLE_ENABLED
#endif

/** Flag values for mbedtls_ssl_context::flags. */
typedef enum {
    /** Set if mbedtls_ssl_set_hostname() has been called. */
    MBEDTLS_SSL_CONTEXT_FLAG_HOSTNAME_SET = 1,
} mbedtls_ssl_context_flags_t;

/** Flags from ::mbedtls_ssl_context_flags_t to keep in
 * mbedtls_ssl_session_reset().
 *
 * The flags that are in this list are kept until explicitly updated or
 * until mbedtls_ssl_free(). The flags that are not listed here are
 * reset to 0 in mbedtls_ssl_session_reset().
 */
#define MBEDTLS_SSL_CONTEXT_FLAGS_KEEP_AT_SESSION       \
    (MBEDTLS_SSL_CONTEXT_FLAG_HOSTNAME_SET)

#define MBEDTLS_SSL_INITIAL_HANDSHAKE           0
#define MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS   1   /* In progress */
#define MBEDTLS_SSL_RENEGOTIATION_DONE          2   /* Done or aborted */
#define MBEDTLS_SSL_RENEGOTIATION_PENDING       3   /* Requested (server only) */

/* Faked handshake message identity for HelloRetryRequest. */
#define MBEDTLS_SSL_TLS1_3_HS_HELLO_RETRY_REQUEST (-MBEDTLS_SSL_HS_SERVER_HELLO)

/*
 * Internal identity of handshake extensions
 */
#define MBEDTLS_SSL_EXT_ID_UNRECOGNIZED                0
#define MBEDTLS_SSL_EXT_ID_SERVERNAME                  1
#define MBEDTLS_SSL_EXT_ID_SERVERNAME_HOSTNAME         1
#define MBEDTLS_SSL_EXT_ID_MAX_FRAGMENT_LENGTH         2
#define MBEDTLS_SSL_EXT_ID_STATUS_REQUEST              3
#define MBEDTLS_SSL_EXT_ID_SUPPORTED_GROUPS            4
#define MBEDTLS_SSL_EXT_ID_SUPPORTED_ELLIPTIC_CURVES   4
#define MBEDTLS_SSL_EXT_ID_SIG_ALG                     5
#define MBEDTLS_SSL_EXT_ID_USE_SRTP                    6
#define MBEDTLS_SSL_EXT_ID_HEARTBEAT                   7
#define MBEDTLS_SSL_EXT_ID_ALPN                        8
#define MBEDTLS_SSL_EXT_ID_SCT                         9
#define MBEDTLS_SSL_EXT_ID_CLI_CERT_TYPE              10
#define MBEDTLS_SSL_EXT_ID_SERV_CERT_TYPE             11
#define MBEDTLS_SSL_EXT_ID_PADDING                    12
#define MBEDTLS_SSL_EXT_ID_PRE_SHARED_KEY             13
#define MBEDTLS_SSL_EXT_ID_EARLY_DATA                 14
#define MBEDTLS_SSL_EXT_ID_SUPPORTED_VERSIONS         15
#define MBEDTLS_SSL_EXT_ID_COOKIE                     16
#define MBEDTLS_SSL_EXT_ID_PSK_KEY_EXCHANGE_MODES     17
#define MBEDTLS_SSL_EXT_ID_CERT_AUTH                  18
#define MBEDTLS_SSL_EXT_ID_OID_FILTERS                19
#define MBEDTLS_SSL_EXT_ID_POST_HANDSHAKE_AUTH        20
#define MBEDTLS_SSL_EXT_ID_SIG_ALG_CERT               21
#define MBEDTLS_SSL_EXT_ID_KEY_SHARE                  22
#define MBEDTLS_SSL_EXT_ID_TRUNCATED_HMAC             23
#define MBEDTLS_SSL_EXT_ID_SUPPORTED_POINT_FORMATS    24
#define MBEDTLS_SSL_EXT_ID_ENCRYPT_THEN_MAC           25
#define MBEDTLS_SSL_EXT_ID_EXTENDED_MASTER_SECRET     26
#define MBEDTLS_SSL_EXT_ID_SESSION_TICKET             27
#define MBEDTLS_SSL_EXT_ID_RECORD_SIZE_LIMIT          28

/* Utility for translating IANA extension type. */
uint32_t mbedtls_ssl_get_extension_id(unsigned int extension_type);
uint32_t mbedtls_ssl_get_extension_mask(unsigned int extension_type);
/* Macros used to define mask constants */
#define MBEDTLS_SSL_EXT_MASK(id)       (1ULL << (MBEDTLS_SSL_EXT_ID_##id))
/* Reset value of extension mask */
#define MBEDTLS_SSL_EXT_MASK_NONE                                              0

/* In messages containing extension requests, we should ignore unrecognized
 * extensions. In messages containing extension responses, unrecognized
 * extensions should result in handshake abortion. Messages containing
 * extension requests include ClientHello, CertificateRequest and
 * NewSessionTicket. Messages containing extension responses include
 * ServerHello, HelloRetryRequest, EncryptedExtensions and Certificate.
 *
 * RFC 8446 section 4.1.3
 *
 * The ServerHello MUST only include extensions which are required to establish
 * the cryptographic context and negotiate the protocol version.
 *
 * RFC 8446 section 4.2
 *
 * If an implementation receives an extension which it recognizes and which is
 * not specified for the message in which it appears, it MUST abort the handshake
 * with an "illegal_parameter" alert.
 */

/* Extensions that are not recognized by TLS 1.3 */
#define MBEDTLS_SSL_TLS1_3_EXT_MASK_UNRECOGNIZED                               \
    (MBEDTLS_SSL_EXT_MASK(SUPPORTED_POINT_FORMATS)                | \
     MBEDTLS_SSL_EXT_MASK(ENCRYPT_THEN_MAC)                       | \
     MBEDTLS_SSL_EXT_MASK(EXTENDED_MASTER_SECRET)                 | \
     MBEDTLS_SSL_EXT_MASK(SESSION_TICKET)                         | \
     MBEDTLS_SSL_EXT_MASK(TRUNCATED_HMAC)                         | \
     MBEDTLS_SSL_EXT_MASK(UNRECOGNIZED))

/* RFC 8446 section 4.2. Allowed extensions for ClientHello */
#define MBEDTLS_SSL_TLS1_3_ALLOWED_EXTS_OF_CH                                  \
    (MBEDTLS_SSL_EXT_MASK(SERVERNAME)                             | \
     MBEDTLS_SSL_EXT_MASK(MAX_FRAGMENT_LENGTH)                    | \
     MBEDTLS_SSL_EXT_MASK(STATUS_REQUEST)                         | \
     MBEDTLS_SSL_EXT_MASK(SUPPORTED_GROUPS)                       | \
     MBEDTLS_SSL_EXT_MASK(SIG_ALG)                                | \
     MBEDTLS_SSL_EXT_MASK(USE_SRTP)                               | \
     MBEDTLS_SSL_EXT_MASK(HEARTBEAT)                              | \
     MBEDTLS_SSL_EXT_MASK(ALPN)                                   | \
     MBEDTLS_SSL_EXT_MASK(SCT)                                    | \
     MBEDTLS_SSL_EXT_MASK(CLI_CERT_TYPE)                          | \
     MBEDTLS_SSL_EXT_MASK(SERV_CERT_TYPE)                         | \
     MBEDTLS_SSL_EXT_MASK(PADDING)                                | \
     MBEDTLS_SSL_EXT_MASK(KEY_SHARE)                              | \
     MBEDTLS_SSL_EXT_MASK(PRE_SHARED_KEY)                         | \
     MBEDTLS_SSL_EXT_MASK(PSK_KEY_EXCHANGE_MODES)                 | \
     MBEDTLS_SSL_EXT_MASK(EARLY_DATA)                             | \
     MBEDTLS_SSL_EXT_MASK(COOKIE)                                 | \
     MBEDTLS_SSL_EXT_MASK(SUPPORTED_VERSIONS)                     | \
     MBEDTLS_SSL_EXT_MASK(CERT_AUTH)                              | \
     MBEDTLS_SSL_EXT_MASK(POST_HANDSHAKE_AUTH)                    | \
     MBEDTLS_SSL_EXT_MASK(SIG_ALG_CERT)                           | \
     MBEDTLS_SSL_EXT_MASK(RECORD_SIZE_LIMIT)                      | \
     MBEDTLS_SSL_TLS1_3_EXT_MASK_UNRECOGNIZED)

/* RFC 8446 section 4.2. Allowed extensions for EncryptedExtensions */
#define MBEDTLS_SSL_TLS1_3_ALLOWED_EXTS_OF_EE                                  \
    (MBEDTLS_SSL_EXT_MASK(SERVERNAME)                             | \
     MBEDTLS_SSL_EXT_MASK(MAX_FRAGMENT_LENGTH)                    | \
     MBEDTLS_SSL_EXT_MASK(SUPPORTED_GROUPS)                       | \
     MBEDTLS_SSL_EXT_MASK(USE_SRTP)                               | \
     MBEDTLS_SSL_EXT_MASK(HEARTBEAT)                              | \
     MBEDTLS_SSL_EXT_MASK(ALPN)                                   | \
     MBEDTLS_SSL_EXT_MASK(CLI_CERT_TYPE)                          | \
     MBEDTLS_SSL_EXT_MASK(SERV_CERT_TYPE)                         | \
     MBEDTLS_SSL_EXT_MASK(EARLY_DATA)                             | \
     MBEDTLS_SSL_EXT_MASK(RECORD_SIZE_LIMIT))

/* RFC 8446 section 4.2. Allowed extensions for CertificateRequest */
#define MBEDTLS_SSL_TLS1_3_ALLOWED_EXTS_OF_CR                                  \
    (MBEDTLS_SSL_EXT_MASK(STATUS_REQUEST)                         | \
     MBEDTLS_SSL_EXT_MASK(SIG_ALG)                                | \
     MBEDTLS_SSL_EXT_MASK(SCT)                                    | \
     MBEDTLS_SSL_EXT_MASK(CERT_AUTH)                              | \
     MBEDTLS_SSL_EXT_MASK(OID_FILTERS)                            | \
     MBEDTLS_SSL_EXT_MASK(SIG_ALG_CERT)                           | \
     MBEDTLS_SSL_TLS1_3_EXT_MASK_UNRECOGNIZED)

/* RFC 8446 section 4.2. Allowed extensions for Certificate */
#define MBEDTLS_SSL_TLS1_3_ALLOWED_EXTS_OF_CT                                  \
    (MBEDTLS_SSL_EXT_MASK(STATUS_REQUEST)                         | \
     MBEDTLS_SSL_EXT_MASK(SCT))

/* RFC 8446 section 4.2. Allowed extensions for ServerHello */
#define MBEDTLS_SSL_TLS1_3_ALLOWED_EXTS_OF_SH                                  \
    (MBEDTLS_SSL_EXT_MASK(KEY_SHARE)                              | \
     MBEDTLS_SSL_EXT_MASK(PRE_SHARED_KEY)                         | \
     MBEDTLS_SSL_EXT_MASK(SUPPORTED_VERSIONS))

/* RFC 8446 section 4.2. Allowed extensions for HelloRetryRequest */
#define MBEDTLS_SSL_TLS1_3_ALLOWED_EXTS_OF_HRR                                 \
    (MBEDTLS_SSL_EXT_MASK(KEY_SHARE)                              | \
     MBEDTLS_SSL_EXT_MASK(COOKIE)                                 | \
     MBEDTLS_SSL_EXT_MASK(SUPPORTED_VERSIONS))

/* RFC 8446 section 4.2. Allowed extensions for NewSessionTicket */
#define MBEDTLS_SSL_TLS1_3_ALLOWED_EXTS_OF_NST                                 \
    (MBEDTLS_SSL_EXT_MASK(EARLY_DATA)                             | \
     MBEDTLS_SSL_TLS1_3_EXT_MASK_UNRECOGNIZED)

#if defined(MBEDTLS_SSL_EARLY_DATA)
typedef enum {
/*
 * The client has not sent the first ClientHello yet, the negotiation of early
 * data has not started yet.
 */
    MBEDTLS_SSL_EARLY_DATA_STATE_IDLE,

/*
 * In its ClientHello, the client has not included an early data indication
 * extension.
 */
    MBEDTLS_SSL_EARLY_DATA_STATE_NO_IND_SENT,

/*
 * The client has sent an early data indication extension in its first
 * ClientHello, it has not received the response (ServerHello or
 * HelloRetryRequest) from the server yet. The transform to protect early data
 * is not set either as for middlebox compatibility a dummy CCS may have to be
 * sent in clear. Early data cannot be sent to the server yet.
 */
    MBEDTLS_SSL_EARLY_DATA_STATE_IND_SENT,

/*
 * The client has sent an early data indication extension in its first
 * ClientHello, it has not received the response (ServerHello or
 * HelloRetryRequest) from the server yet. The transform to protect early data
 * has been set and early data can be written now.
 */
    MBEDTLS_SSL_EARLY_DATA_STATE_CAN_WRITE,

/*
 * The client has indicated the use of early data and the server has accepted
 * it.
 */
    MBEDTLS_SSL_EARLY_DATA_STATE_ACCEPTED,

/*
 * The client has indicated the use of early data but the server has rejected
 * it.
 */
    MBEDTLS_SSL_EARLY_DATA_STATE_REJECTED,

/*
 * The client has sent an early data indication extension in its first
 * ClientHello, the server has accepted them and the client has received the
 * server Finished message. It cannot send early data to the server anymore.
 */
    MBEDTLS_SSL_EARLY_DATA_STATE_SERVER_FINISHED_RECEIVED,

} mbedtls_ssl_early_data_state;
#endif /* MBEDTLS_SSL_EARLY_DATA */

/* cipher.h exports the maximum IV, key and block length from
 * all ciphers enabled in the config, regardless of whether those
 * ciphers are actually usable in SSL/TLS. Notably, XTS is enabled
 * in the default configuration and uses 64 Byte keys, but it is
 * not used for record protection in SSL/TLS.
 *
 * In order to prevent unnecessary inflation of key structures,
 * we introduce SSL-specific variants of the max-{key,block,IV}
 * macros here which are meant to only take those ciphers into
 * account which can be negotiated in SSL/TLS.
 *
 * Since the current definitions of MBEDTLS_MAX_{KEY|BLOCK|IV}_LENGTH
 * in cipher.h are rough overapproximations of the real maxima, here
 * we content ourselves with replicating those overapproximations
 * for the maximum block and IV length, and excluding XTS from the
 * computation of the maximum key length. */
#define MBEDTLS_SSL_MAX_BLOCK_LENGTH 16
#define MBEDTLS_SSL_MAX_IV_LENGTH    16
#define MBEDTLS_SSL_MAX_KEY_LENGTH   32

/**
 * \brief   The data structure holding the cryptographic material (key and IV)
 *          used for record protection in TLS 1.3.
 */
struct mbedtls_ssl_key_set {
    /*! The key for client->server records. */
    unsigned char client_write_key[MBEDTLS_SSL_MAX_KEY_LENGTH];
    /*! The key for server->client records. */
    unsigned char server_write_key[MBEDTLS_SSL_MAX_KEY_LENGTH];
    /*! The IV  for client->server records. */
    unsigned char client_write_iv[MBEDTLS_SSL_MAX_IV_LENGTH];
    /*! The IV  for server->client records. */
    unsigned char server_write_iv[MBEDTLS_SSL_MAX_IV_LENGTH];

    size_t key_len; /*!< The length of client_write_key and
                     *   server_write_key, in Bytes. */
    size_t iv_len;  /*!< The length of client_write_iv and
                     *   server_write_iv, in Bytes. */
};
typedef struct mbedtls_ssl_key_set mbedtls_ssl_key_set;

typedef struct {
    unsigned char binder_key[MBEDTLS_TLS1_3_MD_MAX_SIZE];
    unsigned char client_early_traffic_secret[MBEDTLS_TLS1_3_MD_MAX_SIZE];
    unsigned char early_exporter_master_secret[MBEDTLS_TLS1_3_MD_MAX_SIZE];
} mbedtls_ssl_tls13_early_secrets;

typedef struct {
    unsigned char client_handshake_traffic_secret[MBEDTLS_TLS1_3_MD_MAX_SIZE];
    unsigned char server_handshake_traffic_secret[MBEDTLS_TLS1_3_MD_MAX_SIZE];
} mbedtls_ssl_tls13_handshake_secrets;

typedef int  mbedtls_ssl_tls_prf_cb(const unsigned char *secret, size_t slen,
                                    const char *label,
                                    const unsigned char *random, size_t rlen,
                                    unsigned char *dstbuf, size_t dlen);

/*
 * This structure contains the parameters only needed during handshake.
 */
struct mbedtls_ssl_handshake_params {
    /* Frequently-used boolean or byte fields (placed early to take
     * advantage of smaller code size for indirect access on Arm Thumb) */
    uint8_t resume;                     /*!<  session resume indicator*/
    uint8_t cli_exts;                   /*!< client extension presence*/

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    uint8_t sni_authmode;               /*!< authmode from SNI callback     */
#endif

#if defined(MBEDTLS_SSL_SRV_C)
    /* Flag indicating if a CertificateRequest message has been sent
     * to the client or not. */
    uint8_t certificate_request_sent;
#if defined(MBEDTLS_SSL_EARLY_DATA)
    /* Flag indicating if the server has accepted early data or not. */
    uint8_t early_data_accepted;
#endif
#endif /* MBEDTLS_SSL_SRV_C */

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    uint8_t new_session_ticket;         /*!< use NewSessionTicket?    */
#endif /* MBEDTLS_SSL_SESSION_TICKETS */

#if defined(MBEDTLS_SSL_CLI_C)
    /** Minimum TLS version to be negotiated.
     *
     * It is set up in the ClientHello writing preparation stage and used
     * throughout the ClientHello writing. Not relevant anymore as soon as
     * the protocol version has been negotiated thus as soon as the
     * ServerHello is received.
     * For a fresh handshake not linked to any previous handshake, it is
     * equal to the configured minimum minor version to be negotiated. When
     * renegotiating or resuming a session, it is equal to the previously
     * negotiated minor version.
     *
     * There is no maximum TLS version field in this handshake context.
     * From the start of the handshake, we need to define a current protocol
     * version for the record layer which we define as the maximum TLS
     * version to be negotiated. The `tls_version` field of the SSL context is
     * used to store this maximum value until it contains the actual
     * negotiated value.
     */
    mbedtls_ssl_protocol_version min_tls_version;
#endif

#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    uint8_t extended_ms;                /*!< use Extended Master Secret? */
#endif

#if defined(MBEDTLS_SSL_ASYNC_PRIVATE)
    uint8_t async_in_progress; /*!< an asynchronous operation is in progress */
#endif /* MBEDTLS_SSL_ASYNC_PRIVATE */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    unsigned char retransmit_state;     /*!<  Retransmission state           */
#endif

#if defined(MBEDTLS_SSL_ECP_RESTARTABLE_ENABLED)
    uint8_t ecrs_enabled;               /*!< Handshake supports EC restart? */
    enum { /* this complements ssl->state with info on intra-state operations */
        ssl_ecrs_none = 0,              /*!< nothing going on (yet)         */
        ssl_ecrs_crt_verify,            /*!< Certificate: crt_verify()      */
        ssl_ecrs_ske_start_processing,  /*!< ServerKeyExchange: pk_verify() */
        ssl_ecrs_cke_ecdh_calc_secret,  /*!< ClientKeyExchange: ECDH step 2 */
        ssl_ecrs_crt_vrfy_sign,         /*!< CertificateVerify: pk_sign()   */
    } ecrs_state;                       /*!< current (or last) operation    */
    mbedtls_x509_crt *ecrs_peer_cert;   /*!< The peer's CRT chain.          */
    size_t ecrs_n;                      /*!< place for saving a length      */
#endif

    mbedtls_ssl_ciphersuite_t const *ciphersuite_info;

    MBEDTLS_CHECK_RETURN_CRITICAL
    int (*update_checksum)(mbedtls_ssl_context *, const unsigned char *, size_t);
    MBEDTLS_CHECK_RETURN_CRITICAL
    int (*calc_verify)(const mbedtls_ssl_context *, unsigned char *, size_t *);
    MBEDTLS_CHECK_RETURN_CRITICAL
    int (*calc_finished)(mbedtls_ssl_context *, unsigned char *, int);
    mbedtls_ssl_tls_prf_cb *tls_prf;

    /*
     * Handshake specific crypto variables
     */
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    uint8_t key_exchange_mode; /*!< Selected key exchange mode */

    /**
     * Flag indicating if, in the course of the current handshake, an
     * HelloRetryRequest message has been sent by the server or received by
     * the client (<> 0) or not (0).
     */
    uint8_t hello_retry_request_flag;

#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
    /**
     * Flag indicating if, in the course of the current handshake, a dummy
     * change_cipher_spec (CCS) record has already been sent. Used to send only
     * one CCS per handshake while not complicating the handshake state
     * transitions for that purpose.
     */
    uint8_t ccs_sent;
#endif

#if defined(MBEDTLS_SSL_SRV_C)
#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_PSK_ENABLED)
    uint8_t tls13_kex_modes; /*!< Key exchange modes supported by the client */
#endif
    /** selected_group of key_share extension in HelloRetryRequest message. */
    uint16_t hrr_selected_group;
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    uint16_t new_session_tickets_count;         /*!< number of session tickets */
#endif
#endif /* MBEDTLS_SSL_SRV_C */

#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
    uint16_t received_sig_algs[MBEDTLS_RECEIVED_SIG_ALGS_SIZE];
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_XXDH_PSA_ANY_ENABLED)
    psa_key_type_t xxdh_psa_type;
    size_t xxdh_psa_bits;
    mbedtls_svc_key_id_t xxdh_psa_privkey;
    uint8_t xxdh_psa_privkey_is_external;
    unsigned char xxdh_psa_peerkey[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE];
    size_t xxdh_psa_peerkey_len;
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_XXDH_PSA_ANY_ENABLED */

#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    psa_pake_operation_t psa_pake_ctx;        /*!< EC J-PAKE key exchange */
    mbedtls_svc_key_id_t psa_pake_password;
    uint8_t psa_pake_ctx_is_ok;
#if defined(MBEDTLS_SSL_CLI_C)
    unsigned char *ecjpake_cache;               /*!< Cache for ClientHello ext */
    size_t ecjpake_cache_len;                   /*!< Length of cached data */
#endif
#endif /* MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_ANY_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ANY_ALLOWED_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    uint16_t *curves_tls_id;      /*!<  List of TLS IDs of supported elliptic curves */
#endif

#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED)
    mbedtls_svc_key_id_t psk_opaque;            /*!< Opaque PSK from the callback   */
    uint8_t psk_opaque_is_internal;
    uint16_t    selected_identity;
#endif /* MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED */

#if defined(MBEDTLS_SSL_ECP_RESTARTABLE_ENABLED)
    mbedtls_x509_crt_restart_ctx ecrs_ctx;  /*!< restart context            */
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_ssl_key_cert *key_cert;     /*!< chosen key/cert pair (server)  */
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    mbedtls_ssl_key_cert *sni_key_cert; /*!< key/cert list from SNI         */
    mbedtls_x509_crt *sni_ca_chain;     /*!< trusted CAs from SNI callback  */
    mbedtls_x509_crl *sni_ca_crl;       /*!< trusted CAs CRLs from SNI      */
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_X509_CRT_PARSE_C) &&        \
    !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    mbedtls_pk_context peer_pubkey;     /*!< The public key from the peer.  */
#endif /* MBEDTLS_X509_CRT_PARSE_C && !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */

    struct {
        size_t total_bytes_buffered; /*!< Cumulative size of heap allocated
                                      *   buffers used for message buffering. */

        uint8_t seen_ccs;               /*!< Indicates if a CCS message has
                                         *   been seen in the current flight. */

        struct mbedtls_ssl_hs_buffer {
            unsigned is_valid      : 1;
            unsigned is_fragmented : 1;
            unsigned is_complete   : 1;
            unsigned char *data;
            size_t data_len;
        } hs[MBEDTLS_SSL_MAX_BUFFERED_HS];

        struct {
            unsigned char *data;
            size_t len;
            unsigned epoch;
        } future_record;

    } buffering;

#if defined(MBEDTLS_SSL_CLI_C) && \
    (defined(MBEDTLS_SSL_PROTO_DTLS) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_3))
    unsigned char *cookie;              /*!< HelloVerifyRequest cookie for DTLS
                                         *   HelloRetryRequest cookie for TLS 1.3 */
#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
    /* RFC 6347 page 15
       ...
       opaque cookie<0..2^8-1>;
       ...
     */
    uint8_t cookie_len;
#else
    /* RFC 8446 page 39
       ...
       opaque cookie<0..2^16-1>;
       ...
       If TLS1_3 is enabled, the max length is 2^16 - 1
     */
    uint16_t cookie_len;                /*!< DTLS: HelloVerifyRequest cookie length
                                         *   TLS1_3: HelloRetryRequest cookie length */
#endif
#endif /* MBEDTLS_SSL_CLI_C &&
          ( MBEDTLS_SSL_PROTO_DTLS ||
            MBEDTLS_SSL_PROTO_TLS1_3 ) */
#if defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_PROTO_DTLS)
    unsigned char cookie_verify_result; /*!< Srv: flag for sending a cookie */
#endif /* MBEDTLS_SSL_SRV_C && MBEDTLS_SSL_PROTO_DTLS */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    unsigned int out_msg_seq;           /*!<  Outgoing handshake sequence number */
    unsigned int in_msg_seq;            /*!<  Incoming handshake sequence number */

    uint32_t retransmit_timeout;        /*!<  Current value of timeout       */
    mbedtls_ssl_flight_item *flight;    /*!<  Current outgoing flight        */
    mbedtls_ssl_flight_item *cur_msg;   /*!<  Current message in flight      */
    unsigned char *cur_msg_p;           /*!<  Position in current message    */
    unsigned int in_flight_start_seq;   /*!<  Minimum message sequence in the
                                              flight being received          */
    mbedtls_ssl_transform *alt_transform_out;   /*!<  Alternative transform for
                                                   resending messages             */
    unsigned char alt_out_ctr[MBEDTLS_SSL_SEQUENCE_NUMBER_LEN]; /*!<  Alternative record epoch/counter
                                                                      for resending messages         */

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    /* The state of CID configuration in this handshake. */

    uint8_t cid_in_use; /*!< This indicates whether the use of the CID extension
                         *   has been negotiated. Possible values are
                         *   #MBEDTLS_SSL_CID_ENABLED and
                         *   #MBEDTLS_SSL_CID_DISABLED. */
    unsigned char peer_cid[MBEDTLS_SSL_CID_OUT_LEN_MAX];   /*! The peer's CID */
    uint8_t peer_cid_len;                                  /*!< The length of
                                                            *   \c peer_cid.  */
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

    uint16_t mtu;                       /*!<  Handshake mtu, used to fragment outgoing messages */
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    /*
     * Checksum contexts
     */
#if defined(PSA_WANT_ALG_SHA_256)
    psa_hash_operation_t fin_sha256_psa;
#endif
#if defined(PSA_WANT_ALG_SHA_384)
    psa_hash_operation_t fin_sha384_psa;
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    uint16_t offered_group_id; /* The NamedGroup value for the group
                                * that is being used for ephemeral
                                * key exchange.
                                *
                                * On the client: Defaults to the first
                                * entry in the client's group list,
                                * but can be overwritten by the HRR. */
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

#if defined(MBEDTLS_SSL_CLI_C)
    uint8_t client_auth;       /*!< used to check if CertificateRequest has been
                                    received from server side. If CertificateRequest
                                    has been received, Certificate and CertificateVerify
                                    should be sent to server */
#endif /* MBEDTLS_SSL_CLI_C */
    /*
     * State-local variables used during the processing
     * of a specific handshake state.
     */
    union {
        /* Outgoing Finished message */
        struct {
            uint8_t preparation_done;

            /* Buffer holding digest of the handshake up to
             * but excluding the outgoing finished message. */
            unsigned char digest[MBEDTLS_TLS1_3_MD_MAX_SIZE];
            size_t digest_len;
        } finished_out;

        /* Incoming Finished message */
        struct {
            uint8_t preparation_done;

            /* Buffer holding digest of the handshake up to but
             * excluding the peer's incoming finished message. */
            unsigned char digest[MBEDTLS_TLS1_3_MD_MAX_SIZE];
            size_t digest_len;
        } finished_in;

    } state_local;

    /* End of state-local variables. */

    unsigned char randbytes[MBEDTLS_CLIENT_HELLO_RANDOM_LEN +
                            MBEDTLS_SERVER_HELLO_RANDOM_LEN];
    /*!<  random bytes            */
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    unsigned char premaster[MBEDTLS_PREMASTER_SIZE];
    /*!<  premaster secret        */
    size_t pmslen;                      /*!<  premaster length        */
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    uint32_t sent_extensions;       /*!< extensions sent by endpoint */
    uint32_t received_extensions;   /*!< extensions received by endpoint */

#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
    unsigned char certificate_request_context_len;
    unsigned char *certificate_request_context;
#endif

    /** TLS 1.3 transform for encrypted handshake messages. */
    mbedtls_ssl_transform *transform_handshake;
    union {
        unsigned char early[MBEDTLS_TLS1_3_MD_MAX_SIZE];
        unsigned char handshake[MBEDTLS_TLS1_3_MD_MAX_SIZE];
        unsigned char app[MBEDTLS_TLS1_3_MD_MAX_SIZE];
    } tls13_master_secrets;

    mbedtls_ssl_tls13_handshake_secrets tls13_hs_secrets;
#if defined(MBEDTLS_SSL_EARLY_DATA)
    /** TLS 1.3 transform for early data and handshake messages. */
    mbedtls_ssl_transform *transform_earlydata;
#endif
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

#if defined(MBEDTLS_SSL_ASYNC_PRIVATE)
    /** Asynchronous operation context. This field is meant for use by the
     * asynchronous operation callbacks (mbedtls_ssl_config::f_async_sign_start,
     * mbedtls_ssl_config::f_async_resume, mbedtls_ssl_config::f_async_cancel).
     * The library does not use it internally. */
    void *user_async_ctx;
#endif /* MBEDTLS_SSL_ASYNC_PRIVATE */

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    const unsigned char *sni_name;      /*!< raw SNI                        */
    size_t sni_name_len;                /*!< raw SNI len                    */
#if defined(MBEDTLS_KEY_EXCHANGE_CERT_REQ_ALLOWED_ENABLED)
    const mbedtls_x509_crt *dn_hints;   /*!< acceptable client cert issuers */
#endif
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */
};

typedef struct mbedtls_ssl_hs_buffer mbedtls_ssl_hs_buffer;

/*
 * Representation of decryption/encryption transformations on records
 *
 * There are the following general types of record transformations:
 * - Stream transformations (TLS versions == 1.2 only)
 *   Transformation adding a MAC and applying a stream-cipher
 *   to the authenticated message.
 * - CBC block cipher transformations ([D]TLS versions == 1.2 only)
 *   For TLS 1.2, no IV is generated at key extraction time, but every
 *   encrypted record is explicitly prefixed by the IV with which it was
 *   encrypted.
 * - AEAD transformations ([D]TLS versions == 1.2 only)
 *   These come in two fundamentally different versions, the first one
 *   used in TLS 1.2, excluding ChaChaPoly ciphersuites, and the second
 *   one used for ChaChaPoly ciphersuites in TLS 1.2 as well as for TLS 1.3.
 *   In the first transformation, the IV to be used for a record is obtained
 *   as the concatenation of an explicit, static 4-byte IV and the 8-byte
 *   record sequence number, and explicitly prepending this sequence number
 *   to the encrypted record. In contrast, in the second transformation
 *   the IV is obtained by XOR'ing a static IV obtained at key extraction
 *   time with the 8-byte record sequence number, without prepending the
 *   latter to the encrypted record.
 *
 * Additionally, DTLS 1.2 + CID as well as TLS 1.3 use an inner plaintext
 * which allows to add flexible length padding and to hide a record's true
 * content type.
 *
 * In addition to type and version, the following parameters are relevant:
 * - The symmetric cipher algorithm to be used.
 * - The (static) encryption/decryption keys for the cipher.
 * - For stream/CBC, the type of message digest to be used.
 * - For stream/CBC, (static) encryption/decryption keys for the digest.
 * - For AEAD transformations, the size (potentially 0) of an explicit,
 *   random initialization vector placed in encrypted records.
 * - For some transformations (currently AEAD) an implicit IV. It is static
 *   and (if present) is combined with the explicit IV in a transformation-
 *   -dependent way (e.g. appending in TLS 1.2 and XOR'ing in TLS 1.3).
 * - For stream/CBC, a flag determining the order of encryption and MAC.
 * - The details of the transformation depend on the SSL/TLS version.
 * - The length of the authentication tag.
 *
 * The struct below refines this abstract view as follows:
 * - The cipher underlying the transformation is managed in
 *   cipher contexts cipher_ctx_{enc/dec}, which must have the
 *   same cipher type. The mode of these cipher contexts determines
 *   the type of the transformation in the sense above: e.g., if
 *   the type is MBEDTLS_CIPHER_AES_256_CBC resp. MBEDTLS_CIPHER_AES_192_GCM
 *   then the transformation has type CBC resp. AEAD.
 * - The cipher keys are never stored explicitly but
 *   are maintained within cipher_ctx_{enc/dec}.
 * - For stream/CBC transformations, the message digest contexts
 *   used for the MAC's are stored in md_ctx_{enc/dec}. These contexts
 *   are unused for AEAD transformations.
 * - For stream/CBC transformations, the MAC keys are not stored explicitly
 *   but maintained within md_ctx_{enc/dec}.
 * - The mac_enc and mac_dec fields are unused for EAD transformations.
 * - For transformations using an implicit IV maintained within
 *   the transformation context, its contents are stored within
 *   iv_{enc/dec}.
 * - The value of ivlen indicates the length of the IV.
 *   This is redundant in case of stream/CBC transformations
 *   which always use 0 resp. the cipher's block length as the
 *   IV length, but is needed for AEAD ciphers and may be
 *   different from the underlying cipher's block length
 *   in this case.
 * - The field fixed_ivlen is nonzero for AEAD transformations only
 *   and indicates the length of the static part of the IV which is
 *   constant throughout the communication, and which is stored in
 *   the first fixed_ivlen bytes of the iv_{enc/dec} arrays.
 * - tls_version denotes the 2-byte TLS version
 * - For stream/CBC transformations, maclen denotes the length of the
 *   authentication tag, while taglen is unused and 0.
 * - For AEAD transformations, taglen denotes the length of the
 *   authentication tag, while maclen is unused and 0.
 * - For CBC transformations, encrypt_then_mac determines the
 *   order of encryption and authentication. This field is unused
 *   in other transformations.
 *
 */
struct mbedtls_ssl_transform {
    /*
     * Session specific crypto layer
     */
    size_t minlen;                      /*!<  min. ciphertext length  */
    size_t ivlen;                       /*!<  IV length               */
    size_t fixed_ivlen;                 /*!<  Fixed part of IV (AEAD) */
    size_t maclen;                      /*!<  MAC(CBC) len            */
    size_t taglen;                      /*!<  TAG(AEAD) len           */

    unsigned char iv_enc[16];           /*!<  IV (encryption)         */
    unsigned char iv_dec[16];           /*!<  IV (decryption)         */

#if defined(MBEDTLS_SSL_SOME_SUITES_USE_MAC)

    mbedtls_svc_key_id_t psa_mac_enc;           /*!<  MAC (encryption)        */
    mbedtls_svc_key_id_t psa_mac_dec;           /*!<  MAC (decryption)        */
    psa_algorithm_t psa_mac_alg;                /*!<  psa MAC algorithm       */

#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    int encrypt_then_mac;       /*!< flag for EtM activation                */
#endif

#endif /* MBEDTLS_SSL_SOME_SUITES_USE_MAC */

    mbedtls_ssl_protocol_version tls_version;

    mbedtls_svc_key_id_t psa_key_enc;           /*!<  psa encryption key      */
    mbedtls_svc_key_id_t psa_key_dec;           /*!<  psa decryption key      */
    psa_algorithm_t psa_alg;                    /*!<  psa algorithm           */

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    uint8_t in_cid_len;
    uint8_t out_cid_len;
    unsigned char in_cid[MBEDTLS_SSL_CID_IN_LEN_MAX];
    unsigned char out_cid[MBEDTLS_SSL_CID_OUT_LEN_MAX];
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

#if defined(MBEDTLS_SSL_KEEP_RANDBYTES)
    /* We need the Hello random bytes in order to re-derive keys from the
     * Master Secret and other session info and for the keying material
     * exporter in TLS 1.2.
     * See ssl_tls12_populate_transform() */
    unsigned char randbytes[MBEDTLS_SERVER_HELLO_RANDOM_LEN +
                            MBEDTLS_CLIENT_HELLO_RANDOM_LEN];
    /*!< ServerHello.random+ClientHello.random */
#endif /* defined(MBEDTLS_SSL_KEEP_RANDBYTES) */
};

/*
 * Internal representation of record frames
 *
 * Instances come in two flavors:
 * (1) Encrypted
 *     These always have data_offset = 0
 * (2) Unencrypted
 *     These have data_offset set to the amount of
 *     pre-expansion during record protection. Concretely,
 *     this is the length of the fixed part of the explicit IV
 *     used for encryption, or 0 if no explicit IV is used
 *     (e.g. for stream ciphers).
 *
 * The reason for the data_offset in the unencrypted case
 * is to allow for in-place conversion of an unencrypted to
 * an encrypted record. If the offset wasn't included, the
 * encrypted content would need to be shifted afterwards to
 * make space for the fixed IV.
 *
 */
#if MBEDTLS_SSL_CID_OUT_LEN_MAX > MBEDTLS_SSL_CID_IN_LEN_MAX
#define MBEDTLS_SSL_CID_LEN_MAX MBEDTLS_SSL_CID_OUT_LEN_MAX
#else
#define MBEDTLS_SSL_CID_LEN_MAX MBEDTLS_SSL_CID_IN_LEN_MAX
#endif

typedef struct {
    uint8_t ctr[MBEDTLS_SSL_SEQUENCE_NUMBER_LEN];  /* In TLS:  The implicit record sequence number.
                                                    * In DTLS: The 2-byte epoch followed by
                                                    *          the 6-byte sequence number.
                                                    * This is stored as a raw big endian byte array
                                                    * as opposed to a uint64_t because we rarely
                                                    * need to perform arithmetic on this, but do
                                                    * need it as a Byte array for the purpose of
                                                    * MAC computations.                             */
    uint8_t type;           /* The record content type.                      */
    uint8_t ver[2];         /* SSL/TLS version as present on the wire.
                             * Convert to internal presentation of versions
                             * using mbedtls_ssl_read_version() and
                             * mbedtls_ssl_write_version().
                             * Keep wire-format for MAC computations.        */

    unsigned char *buf;     /* Memory buffer enclosing the record content    */
    size_t buf_len;         /* Buffer length                                 */
    size_t data_offset;     /* Offset of record content                      */
    size_t data_len;        /* Length of record content                      */

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    uint8_t cid_len;        /* Length of the CID (0 if not present)          */
    unsigned char cid[MBEDTLS_SSL_CID_LEN_MAX];   /* The CID                 */
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
} mbedtls_record;

#if defined(MBEDTLS_X509_CRT_PARSE_C)
/*
 * List of certificate + private key pairs
 */
struct mbedtls_ssl_key_cert {
    mbedtls_x509_crt *cert;                 /*!< cert                       */
    mbedtls_pk_context *key;                /*!< private key                */
    mbedtls_ssl_key_cert *next;             /*!< next key/cert pair         */
};
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
/*
 * List of handshake messages kept around for resending
 */
struct mbedtls_ssl_flight_item {
    unsigned char *p;       /*!< message, including handshake headers   */
    size_t len;             /*!< length of p                            */
    unsigned char type;     /*!< type of the message: handshake or CCS  */
    mbedtls_ssl_flight_item *next;  /*!< next handshake message(s)              */
};
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#endif /* ssl_types.h */
