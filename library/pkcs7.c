/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#include "x509_internal.h"

#if defined(MBEDTLS_PKCS7_C)
#include "mbedtls/pkcs7.h"
#include "mbedtls/asn1.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_crl.h"
#include "mbedtls/oid.h"
#include "x509_oid.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_FS_IO)
#include <sys/types.h>
#include <sys/stat.h>
#endif

#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include <limits.h>

#if defined(MBEDTLS_HAVE_TIME)
#include "mbedtls/platform_time.h"
#endif
#if defined(MBEDTLS_HAVE_TIME_DATE)
#include <time.h>
#endif

/**
 * Initializes the mbedtls_pkcs7 structure.
 */
void mbedtls_pkcs7_init(mbedtls_pkcs7 *pkcs7)
{
    memset(pkcs7, 0, sizeof(*pkcs7));
}

static int pkcs7_get_next_content_len(unsigned char **p, unsigned char *end,
                                      size_t *len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = mbedtls_asn1_get_tag(p, end, len, MBEDTLS_ASN1_CONSTRUCTED
                               | MBEDTLS_ASN1_CONTEXT_SPECIFIC);
    if (ret != 0) {
        ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO, ret);
    } else if ((size_t) (end - *p) != *len) {
        ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO,
                                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    return ret;
}

/**
 * version Version
 * Version ::= INTEGER
 **/
static int pkcs7_get_version(unsigned char **p, unsigned char *end, int *ver)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = mbedtls_asn1_get_int(p, end, ver);
    if (ret != 0) {
        ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_VERSION, ret);
    }

    /* If version != 1, return invalid version */
    if (*ver != MBEDTLS_PKCS7_SUPPORTED_VERSION) {
        ret = MBEDTLS_ERR_PKCS7_INVALID_VERSION;
    }

    return ret;
}

/**
 * ContentInfo ::= SEQUENCE {
 *      contentType ContentType,
 *      content
 *              [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
 **/
static int pkcs7_get_content_info_type(unsigned char **p, unsigned char *end,
                                       unsigned char **seq_end,
                                       mbedtls_pkcs7_buf *pkcs7)
{
    size_t len = 0;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *start = *p;

    ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
                               | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) {
        *p = start;
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO, ret);
    }
    *seq_end = *p + len;
    ret = mbedtls_asn1_get_tag(p, *seq_end, &len, MBEDTLS_ASN1_OID);
    if (ret != 0) {
        *p = start;
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO, ret);
    }

    pkcs7->tag = MBEDTLS_ASN1_OID;
    pkcs7->len = len;
    pkcs7->p = *p;
    *p += len;

    return ret;
}

/**
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 * This is from x509.h
 **/
static int pkcs7_get_digest_algorithm(unsigned char **p, unsigned char *end,
                                      mbedtls_x509_buf *alg)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if ((ret = mbedtls_asn1_get_alg_null(p, end, alg)) != 0) {
        ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_ALG, ret);
    }

    return ret;
}

/**
 * DigestAlgorithmIdentifiers :: SET of DigestAlgorithmIdentifier
 **/
static int pkcs7_get_digest_algorithm_set(unsigned char **p,
                                          unsigned char *end,
                                          mbedtls_x509_buf *alg)
{
    size_t len = 0;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
                               | MBEDTLS_ASN1_SET);
    if (ret != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_ALG, ret);
    }

    end = *p + len;

    ret = mbedtls_asn1_get_alg_null(p, end, alg);
    if (ret != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_ALG, ret);
    }

    /** For now, it assumes there is only one digest algorithm specified **/
    if (*p != end) {
        return MBEDTLS_ERR_PKCS7_FEATURE_UNAVAILABLE;
    }

    return 0;
}

/**
 * \brief           Parse and add a certificate to the certificate list.
 *
 * \details         Decodes a DER-encoded certificate and adds it to the
 *                  certificate list.
 *
 * \param der_cert  DER-encoded certificate.
 * \param der_len   Length of the DER-encoded certificate.
 * \param certs     Certificate list to which the parsed certificate
 *                  is added.
 *
 * \return          0 on success, or a negative error code on failure.
 */
static int pkcs7_parse_cert_der(const unsigned char *der_cert, size_t der_len,
                                mbedtls_pkcs7_cert **certs)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_pkcs7_cert *pcert;

    pcert = mbedtls_calloc(1, sizeof(mbedtls_pkcs7_cert));
    if (pcert == NULL) {
        return MBEDTLS_ERR_PKCS7_ALLOC_FAILED;
    }

    mbedtls_x509_crt_init(&pcert->cert);

    ret = mbedtls_x509_crt_parse_der(&pcert->cert, der_cert, der_len);
    if (ret != 0) {
        mbedtls_free(pcert);
        return MBEDTLS_ERR_PKCS7_INVALID_CERT;
    }

    if (*certs == NULL) {
        *certs = pcert;
    } else {
        pcert->next = *certs;
        *certs = pcert;
    }

    return 0;
}

/**
 * \brief           Parse certificates from PKCS#7 SignedData.
 *
 * \details         Parses the SET OF ExtendedCertificateOrCertificate and
 *                  stores them in a linked list of mbedtls_pkcs7_cert nodes.
 *
 *                  certificates :: SET OF ExtendedCertificateOrCertificate,
 *                  ExtendedCertificateOrCertificate ::= CHOICE {
 *                       certificate Certificate -- x509,
 *                       extendedCertificate[0] IMPLICIT ExtendedCertificate
 *                  }
 *
 * \param p         Input pointer to ASN.1 buffer.
 * \param end       End of input buffer.
 * \param certs     Certificate list.
 *
 * \return          Number of certificates parsed (>= 0) on success,
 *                  or a negative error code on failure.
 */
static int pkcs7_get_certificates(unsigned char **p, unsigned char *end,
                                  mbedtls_pkcs7_cert **certs)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t set_len = 0;
    int count = 0;
    unsigned char *end_set;

    ret = mbedtls_asn1_get_tag(p, end, &set_len,
                               MBEDTLS_ASN1_CONSTRUCTED |
                               MBEDTLS_ASN1_CONTEXT_SPECIFIC);
    if (ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
        return 0;
    } else if (ret != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_FORMAT, ret);
    }

    end_set = *p + set_len;

    while (*p < end_set && count < INT_MAX) {
        unsigned char *elem_start = *p;
        unsigned char *q = *p;
        size_t cert_len = 0;
        size_t der_len;

        ret = mbedtls_asn1_get_tag(&q, end_set, &cert_len,
                                   MBEDTLS_ASN1_CONSTRUCTED |
                                   MBEDTLS_ASN1_SEQUENCE);
        if (ret != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_CERT,
                                     ret);
        }

        if (cert_len > (size_t) (end_set - q)) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_FORMAT,
                                     MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
        }

        der_len = (size_t) ((q + cert_len) - elem_start);

        ret = pkcs7_parse_cert_der(elem_start, der_len, certs);
        if (ret != 0) {
            return ret;
        }

        *p = q + cert_len;
        count++;
    }

    if (*p != end_set) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_FORMAT,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    return count;
}

/**
 * EncryptedDigest ::= OCTET STRING
 **/
static int pkcs7_get_signature(unsigned char **p, unsigned char *end,
                               mbedtls_pkcs7_buf *signature)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_OCTET_STRING);
    if (ret != 0) {
        return ret;
    }

    signature->tag = MBEDTLS_ASN1_OCTET_STRING;
    signature->len = len;
    signature->p = *p;

    *p = *p + len;

    return 0;
}

static void pkcs7_free_signer_info(mbedtls_pkcs7_signer_info *signer)
{
    mbedtls_x509_name *name_cur;
    mbedtls_x509_name *name_prv;

    if (signer == NULL) {
        return;
    }

    name_cur = signer->issuer.next;
    while (name_cur != NULL) {
        name_prv = name_cur;
        name_cur = name_cur->next;
        mbedtls_free(name_prv);
    }
    signer->issuer.next = NULL;
}

/**
 * SignerInfo ::= SEQUENCE {
 *      version Version;
 *      issuerAndSerialNumber   IssuerAndSerialNumber,
 *      digestAlgorithm DigestAlgorithmIdentifier,
 *      authenticatedAttributes
 *              [0] IMPLICIT Attributes OPTIONAL,
 *      digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
 *      encryptedDigest EncryptedDigest,
 *      unauthenticatedAttributes
 *              [1] IMPLICIT Attributes OPTIONAL,
 * Returns 0 if the signerInfo is valid.
 * Return negative error code for failure.
 * Structure must not contain vales for authenticatedAttributes
 * and unauthenticatedAttributes.
 **/
static int pkcs7_get_signer_info(unsigned char **p, unsigned char *end,
                                 mbedtls_pkcs7_signer_info *signer,
                                 mbedtls_x509_buf *alg)
{
    unsigned char *end_signer, *end_issuer_and_sn;
    int asn1_ret = 0, ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    asn1_ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
                                    | MBEDTLS_ASN1_SEQUENCE);
    if (asn1_ret != 0) {
        goto out;
    }

    end_signer = *p + len;

    ret = pkcs7_get_version(p, end_signer, &signer->version);
    if (ret != 0) {
        goto out;
    }

    asn1_ret = mbedtls_asn1_get_tag(p, end_signer, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (asn1_ret != 0) {
        goto out;
    }

    end_issuer_and_sn = *p + len;
    /* Parsing IssuerAndSerialNumber */
    signer->issuer_raw.p = *p;

    asn1_ret = mbedtls_asn1_get_tag(p, end_issuer_and_sn, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (asn1_ret != 0) {
        goto out;
    }

    ret  = mbedtls_x509_get_name(p, *p + len, &signer->issuer);
    if (ret != 0) {
        goto out;
    }

    signer->issuer_raw.len =  (size_t) (*p - signer->issuer_raw.p);

    ret = mbedtls_x509_get_serial(p, end_issuer_and_sn, &signer->serial);
    if (ret != 0) {
        goto out;
    }

    /* ensure no extra or missing bytes */
    if (*p != end_issuer_and_sn) {
        ret = MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO;
        goto out;
    }

    ret = pkcs7_get_digest_algorithm(p, end_signer, &signer->alg_identifier);
    if (ret != 0) {
        goto out;
    }

    /* Check that the digest algorithm used matches the one provided earlier */
    if (signer->alg_identifier.tag != alg->tag ||
        signer->alg_identifier.len != alg->len ||
        memcmp(signer->alg_identifier.p, alg->p, alg->len) != 0) {
        ret = MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO;
        goto out;
    }

    /* Assume authenticatedAttributes is nonexistent */
    ret = pkcs7_get_digest_algorithm(p, end_signer, &signer->sig_alg_identifier);
    if (ret != 0) {
        goto out;
    }

    ret = pkcs7_get_signature(p, end_signer, &signer->sig);
    if (ret != 0) {
        goto out;
    }

    /* Do not permit any unauthenticated attributes */
    if (*p != end_signer) {
        ret = MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO;
    }

out:
    if (asn1_ret != 0 || ret != 0) {
        pkcs7_free_signer_info(signer);
        ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO,
                                asn1_ret);
    }

    return ret;
}

/**
 * SignerInfos ::= SET of SignerInfo
 * Return number of signers added to the signed data,
 * 0 or higher is valid.
 * Return negative error code for failure.
 **/
static int pkcs7_get_signers_info_set(unsigned char **p, unsigned char *end,
                                      mbedtls_pkcs7_signer_info *signers_set,
                                      mbedtls_x509_buf *digest_alg)
{
    unsigned char *end_set;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int count = 0;
    size_t len = 0;

    ret = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
                               | MBEDTLS_ASN1_SET);
    if (ret != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO, ret);
    }

    /* Detect zero signers */
    if (len == 0) {
        return 0;
    }

    end_set = *p + len;

    ret = pkcs7_get_signer_info(p, end_set, signers_set, digest_alg);
    if (ret != 0) {
        return ret;
    }
    count++;

    mbedtls_pkcs7_signer_info *prev = signers_set;
    while (*p != end_set) {
        mbedtls_pkcs7_signer_info *signer =
            mbedtls_calloc(1, sizeof(mbedtls_pkcs7_signer_info));
        if (!signer) {
            ret = MBEDTLS_ERR_PKCS7_ALLOC_FAILED;
            goto cleanup;
        }

        ret = pkcs7_get_signer_info(p, end_set, signer, digest_alg);
        if (ret != 0) {
            mbedtls_free(signer);
            goto cleanup;
        }
        prev->next = signer;
        prev = signer;
        count++;
    }

    return count;

cleanup:
    pkcs7_free_signer_info(signers_set);
    mbedtls_pkcs7_signer_info *signer = signers_set->next;
    while (signer != NULL) {
        prev = signer;
        signer = signer->next;
        pkcs7_free_signer_info(prev);
        mbedtls_free(prev);
    }
    signers_set->next = NULL;
    return ret;
}

/**
 * SignedData ::= SEQUENCE {
 *      version Version,
 *      digestAlgorithms DigestAlgorithmIdentifiers,
 *      contentInfo ContentInfo,
 *      certificates
 *              [0] IMPLICIT ExtendedCertificatesAndCertificates
 *                  OPTIONAL,
 *      crls
 *              [0] IMPLICIT CertificateRevocationLists OPTIONAL,
 *      signerInfos SignerInfos }
 */
static int pkcs7_get_signed_data(unsigned char *buf, size_t buflen,
                                 mbedtls_pkcs7_signed_data *signed_data)
{
    unsigned char *p = buf;
    unsigned char *end = buf + buflen;
    unsigned char *end_content_info = NULL;
    size_t len = 0;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_md_type_t md_alg;

    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
                               | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_FORMAT, ret);
    }

    if (p + len != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_FORMAT,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    /* Get version of signed data */
    ret = pkcs7_get_version(&p, end, &signed_data->version);
    if (ret != 0) {
        return ret;
    }

    /* Get digest algorithm */
    ret = pkcs7_get_digest_algorithm_set(&p, end,
                                         &signed_data->digest_alg_identifiers);
    if (ret != 0) {
        return ret;
    }

    ret = mbedtls_x509_oid_get_md_alg(&signed_data->digest_alg_identifiers, &md_alg);
    if (ret != 0) {
        return MBEDTLS_ERR_PKCS7_INVALID_ALG;
    }

    mbedtls_pkcs7_buf content_type;
    memset(&content_type, 0, sizeof(content_type));
    ret = pkcs7_get_content_info_type(&p, end, &end_content_info, &content_type);
    if (ret != 0) {
        return ret;
    }
    if (MBEDTLS_OID_CMP(MBEDTLS_OID_PKCS7_DATA, &content_type)) {
        return MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO;
    }

    if (p != end_content_info) {
        /* Determine if valid content is present */
        ret = mbedtls_asn1_get_tag(&p,
                                   end_content_info,
                                   &len,
                                   MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC);
        if (ret != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO, ret);
        }
        p += len;
        if (p != end_content_info) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO, ret);
        }
        /* Valid content is present - this is not supported */
        return MBEDTLS_ERR_PKCS7_FEATURE_UNAVAILABLE;
    }

    /* Look for certificates, there may or may not be any */
    signed_data->certs = NULL;
    ret = pkcs7_get_certificates(&p, end, &signed_data->certs);
    if (ret < 0) {
        return ret;
    }

    signed_data->no_of_certs = ret;
    /*
     * Currently CRLs are not supported. If CRL exist, the parsing will fail
     * at next step of getting signers info and return error as invalid
     * signer info.
     */

    signed_data->no_of_crls = 0;

    /* Get signers info */
    ret = pkcs7_get_signers_info_set(&p,
                                     end,
                                     &signed_data->signers,
                                     &signed_data->digest_alg_identifiers);
    if (ret < 0) {
        return ret;
    }

    signed_data->no_of_signers = ret;

    /* Don't permit trailing data */
    if (p != end) {
        return MBEDTLS_ERR_PKCS7_INVALID_FORMAT;
    }

    return 0;
}

int mbedtls_pkcs7_parse_der(mbedtls_pkcs7 *pkcs7, const unsigned char *buf,
                            const size_t buflen)
{
    unsigned char *p;
    unsigned char *end;
    size_t len = 0;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (pkcs7 == NULL) {
        return MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA;
    }

    /* make an internal copy of the buffer for parsing */
    pkcs7->raw.p = p = mbedtls_calloc(1, buflen);
    if (pkcs7->raw.p == NULL) {
        ret = MBEDTLS_ERR_PKCS7_ALLOC_FAILED;
        goto out;
    }
    memcpy(p, buf, buflen);
    pkcs7->raw.len = buflen;
    end = p + buflen;

    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
                               | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) {
        ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_FORMAT, ret);
        goto out;
    }

    if ((size_t) (end - p) != len) {
        ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS7_INVALID_FORMAT,
                                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
        goto out;
    }

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OID)) != 0) {
        if (ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
            goto out;
        }
        p = pkcs7->raw.p;
        len = buflen;
        goto try_data;
    }

    if (MBEDTLS_OID_CMP_RAW(MBEDTLS_OID_PKCS7_SIGNED_DATA, p, len)) {
        /* OID is not MBEDTLS_OID_PKCS7_SIGNED_DATA, which is the only supported feature */
        if (!MBEDTLS_OID_CMP_RAW(MBEDTLS_OID_PKCS7_DATA, p, len)
            || !MBEDTLS_OID_CMP_RAW(MBEDTLS_OID_PKCS7_ENCRYPTED_DATA, p, len)
            || !MBEDTLS_OID_CMP_RAW(MBEDTLS_OID_PKCS7_ENVELOPED_DATA, p, len)
            || !MBEDTLS_OID_CMP_RAW(MBEDTLS_OID_PKCS7_SIGNED_AND_ENVELOPED_DATA, p, len)
            || !MBEDTLS_OID_CMP_RAW(MBEDTLS_OID_PKCS7_DIGESTED_DATA, p, len)) {
            /* OID is valid according to the spec, but unsupported */
            ret =  MBEDTLS_ERR_PKCS7_FEATURE_UNAVAILABLE;
        } else {
            /* OID is invalid according to the spec */
            ret = MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA;
        }
        goto out;
    }

    p += len;

    ret = pkcs7_get_next_content_len(&p, end, &len);
    if (ret != 0) {
        goto out;
    }

    /* ensure no extra/missing data */
    if (p + len != end) {
        ret = MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA;
        goto out;
    }

try_data:
    ret = pkcs7_get_signed_data(p, len, &pkcs7->signed_data);
    if (ret != 0) {
        goto out;
    }

    ret = MBEDTLS_PKCS7_SIGNED_DATA;

out:
    if (ret < 0) {
        mbedtls_pkcs7_free(pkcs7);
    }

    return ret;
}

/**
 * \brief      Decide whether a certificate should be classified as a CA.
 *             Policy:
 *              - If BasicConstraints present and CA=TRUE => CA
 *              - If KeyUsage is present, require keyCertSign for CA
 *              - If BasicConstraints absent => NOT a CA (classify as leaf)
 *              - If BasicConstraints is present and CA=FALSE => not a CA (leaf)
 *
 * \param crt  Certificate to classify.
 *
 * \return     1 if the certificate is classified as CA, 0 otherwise.
 */
static int pkcs7_is_ca_cert(const mbedtls_x509_crt *crt)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    /* BasicConstraints: is CA? */
    ret = mbedtls_x509_crt_get_ca_istrue(crt);
    if (ret == 1) {
        /* CA=TRUE; enforce keyCertSign only if KU exists  */
        ret = mbedtls_x509_crt_check_key_usage(crt, MBEDTLS_X509_KU_KEY_CERT_SIGN);
        return (ret == 0) ? 1 : 0;
    } else {
        /* ret == 0: BC present, CA=FALSE.  ret < 0: BasicConstraints absent) */
        return 0;
    }
}

/**
 * \brief           Check if the given CA certificate is a possible issuer of
 *                  the provided certificate.
 * \details         This function attempts to match the issuer of \p cert with
 *                  the subject of \p ca using the following order:
 *                  1. If both AKI keyIdentifier and SKI are present, compare them.
 *                  2. If AKI authorityCertIssuer and authorityCertSerialNumber are
 *                     present, compare against the CA's subject DN and serial.
 *                  3. Fallback to comparing issuer and subject Distinguished Name (DN).
 *
 * \param cert      The certificate whose issuer is to be found.
 * \param ca        Candidate CA certificate.
 *
 * \return          0 if \p ca is a potential issuer of \p cert, -1 otherwise.
 */
static int pkcs7_is_issuer_match(const mbedtls_x509_crt *cert,
                                 const mbedtls_x509_crt *ca)
{
    if (cert->authority_key_id.keyIdentifier.len != 0 &&
        ca->subject_key_id.len != 0) {

        if (cert->authority_key_id.keyIdentifier.len == ca->subject_key_id.len &&
            memcmp(cert->authority_key_id.keyIdentifier.p, ca->subject_key_id.p,
                   ca->subject_key_id.len) == 0) {
            return 0;
        }

        return -1;
    }

    if (cert->authority_key_id.authorityCertIssuer.buf.len != 0 &&
        cert->authority_key_id.authorityCertSerialNumber.len != 0) {

        if (cert->authority_key_id.authorityCertIssuer.buf.len == ca->subject_raw.len &&
            memcmp(cert->authority_key_id.authorityCertIssuer.buf.p,
                   ca->subject_raw.p, ca->subject_raw.len) == 0 &&
            cert->authority_key_id.authorityCertSerialNumber.len == ca->serial.len &&
            memcmp(cert->authority_key_id.authorityCertSerialNumber.p,
                   ca->serial.p, ca->serial.len) == 0) {
            return 0;
        }

        return -1;
    }

    if (cert->issuer_raw.len == ca->subject_raw.len &&
        memcmp(cert->issuer_raw.p, ca->subject_raw.p,
               cert->issuer_raw.len) == 0) {
        return 0;
    }

    return -1;
}

/**
 * \brief            Check if a certificate already exist in the chain
 *                   by comparing TBSCertificate content.
 *
 * \param chain      The certificate chain to search
 * \param cert       The certificate to look for
 *
 * \return           1 if certificate exists in chain
 *                   0 if certificate does not exist
 */
static int pkcs7_is_duplicate_cert(const mbedtls_x509_crt *chain,
                                   const mbedtls_x509_crt *cert)
{
    const mbedtls_x509_crt *cur;

    for (cur = chain; cur != NULL; cur = cur->next) {
        if (cur->tbs.len != cert->tbs.len) {
            continue;
        }

        if (memcmp(cur->tbs.p, cert->tbs.p, cert->tbs.len) == 0) {
            return 1;
        }
    }

    return 0;
}

/**
 * \brief              Build CA certificate chain from embedded PKCS#7 certs.
 *
 * \param pkcs7_certs  Embedded certificate list (mbedtls_pkcs7_cert).
 * \param leaf_cert    Leaf certificate to build chain for.
 * \param ca_chain     On success, pointer to CA chain (caller must free).
 *
 * \return             0 on success, or a negative error code on failure.
 */
static int pkcs7_build_ca_chain(const mbedtls_pkcs7_cert *pkcs7_certs,
                                const mbedtls_x509_crt *leaf_cert,
                                mbedtls_x509_crt **ca_chain)
{
    const mbedtls_x509_crt *current = leaf_cert;
    const mbedtls_pkcs7_cert *embedded_cert;
    mbedtls_x509_crt *chain = NULL;
    int ret;
    size_t depth = 0;

    *ca_chain = NULL;

    while (depth < MBEDTLS_X509_MAX_INTERMEDIATE_CA && current != NULL) {
        int found = 0;

        for (embedded_cert = pkcs7_certs; embedded_cert != NULL;
             embedded_cert = embedded_cert->next) {
            const mbedtls_x509_crt *issuer = &embedded_cert->cert;

            if (issuer->raw.p == NULL || issuer->raw.len == 0) {
                continue;
            }

            if (issuer == current) {
                continue;
            }

            if (pkcs7_is_ca_cert(issuer) != 1) {
                continue;
            }

            if (pkcs7_is_issuer_match(current, issuer) == 0) {
                if (pkcs7_is_duplicate_cert(chain, issuer)) {
                    continue;
                }

                if (chain == NULL) {
                    chain = mbedtls_calloc(1, sizeof(mbedtls_x509_crt));
                    if (chain == NULL) {
                        ret =  MBEDTLS_ERR_PKCS7_ALLOC_FAILED;
                        goto cleanup;
                    }
                    mbedtls_x509_crt_init(chain);
                }

                ret = mbedtls_x509_crt_parse_der(chain, issuer->raw.p, issuer->raw.len);
                if (ret != 0) {
                    goto cleanup;
                }

                current = issuer;
                found = 1;
                depth++;
                break;
            }
        }

        if (!found) {
            break;
        }
    }

    *ca_chain = chain;
    return 0;

cleanup:
    if (chain != NULL) {
        mbedtls_x509_crt_free(chain);
        mbedtls_free(chain);
    }
    return ret;
}

/**
 * \brief              Verify certificate chain against trusted anchors.
 *
 * \details            Builds CA chain from embedded PKCS#7 certs and verifies
 *                     the complete chain against trust anchors.
 *
 * \note               mbedtls_x509_crt_verify() accepts mixed list of trusted
 *                     CAs and trusted leaf certs.
 *
 * \param pkcs7_certs    Embedded certificate list
 * \param leaf_cert      Leaf certificate to verify.
 * \param trust_anchors  Trust anchors: root CAs and/or trusted leaf certs.
 *
 * \return               0 on success, or a negative error code on failure.
 */
static int pkcs7_verify_chain(const mbedtls_pkcs7_cert *pkcs7_certs,
                              mbedtls_x509_crt *leaf_cert,
                              const mbedtls_x509_crt *trust_anchors)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_x509_crt *ca_chain = NULL;
    uint32_t flags = 0;

    ret = pkcs7_build_ca_chain(pkcs7_certs, leaf_cert, &ca_chain);
    if (ret != 0) {
        return ret;
    }

    leaf_cert->next = ca_chain;
    ret = mbedtls_x509_crt_verify(leaf_cert, (mbedtls_x509_crt *) trust_anchors,
                                  NULL, NULL, &flags, NULL, NULL);

    leaf_cert->next = NULL;

    if (ca_chain != NULL) {
        mbedtls_x509_crt_free(ca_chain);
        mbedtls_free(ca_chain);
    }

    if (ret != 0 || flags != 0) {
        return MBEDTLS_ERR_PKCS7_CERT_VERIFY_FAILED;
    }

    return 0;
}

/**
 * \brief           Check if certificate matches signer info.
 *
 * \details         Validates certificate date, matches serial/issuer,
 *                  and checks key usage for digital signature.
 *
 * \param cert      Certificate to check.
 * \param signer    Signer info to match against.
 *
 * \return          0 if match, or a negative error code otherwise.
 */
static int pkcs7_check_cert_with_signer(const mbedtls_x509_crt *cert,
                                        const mbedtls_pkcs7_signer_info *signer)
{
    if (cert->raw.p == NULL || cert->raw.len == 0) {
        return MBEDTLS_ERR_PKCS7_INVALID_CERT;
    }

    if (mbedtls_x509_time_is_past(&cert->valid_to) ||
        mbedtls_x509_time_is_future(&cert->valid_from)) {
        return MBEDTLS_ERR_PKCS7_CERT_DATE_INVALID;
    }

    if (cert->serial.len != signer->serial.len ||
        memcmp(cert->serial.p, signer->serial.p, signer->serial.len) != 0) {
        return MBEDTLS_ERR_PKCS7_SIGNER_CERT_NOT_FOUND;
    }

    if (cert->issuer_raw.len != signer->issuer_raw.len ||
        memcmp(cert->issuer_raw.p, signer->issuer_raw.p,
               signer->issuer_raw.len) != 0) {
        return MBEDTLS_ERR_PKCS7_SIGNER_CERT_NOT_FOUND;
    }

    if (mbedtls_x509_crt_check_key_usage(cert,
                                         MBEDTLS_X509_KU_DIGITAL_SIGNATURE) != 0) {
        return MBEDTLS_ERR_PKCS7_SIGNER_CERT_NOT_FOUND;
    }

    return 0;
}

/**
 * \brief                Find matching leaf certificate.
 *
 * \details              Searches for certificate matching signer info.
 *                       Can search in embedded PKCS#7 certs or external chain.
 *
 * \param pkcs7          PKCS#7 structure (for embedded certs).
 * \param certs          External certificate chain.
 * \param signer         Signer info to match against.
 * \param use_pkcs7_leaf Flag: 1=search embedded, 0=search external.
 * \param leaf_cert      On success, pointer to matching certificate.
 *
 * \return               0 on success, or a negative error code on failure.
 */
static int pkcs7_get_leaf_cert(const mbedtls_pkcs7 *pkcs7,
                               const mbedtls_x509_crt *certs,
                               const mbedtls_pkcs7_signer_info *signer,
                               const int use_pkcs7_leaf,
                               mbedtls_x509_crt **leaf_cert)
{
    int ret = MBEDTLS_ERR_PKCS7_SIGNER_CERT_NOT_FOUND;

    if (use_pkcs7_leaf == 1) {
        const mbedtls_pkcs7_cert *embedded_cert = pkcs7->signed_data.certs;

        while (embedded_cert != NULL) {
            const mbedtls_x509_crt *cert = &embedded_cert->cert;

            ret = pkcs7_check_cert_with_signer(cert, signer);
            if (ret == 0) {
                *leaf_cert = (mbedtls_x509_crt *) cert;
                return 0;
            }

            embedded_cert = embedded_cert->next;
        }
    } else {
        const mbedtls_x509_crt *cert = certs;

        while (cert != NULL) {
            ret = pkcs7_check_cert_with_signer(cert, signer);
            if (ret == 0) {
                *leaf_cert = (mbedtls_x509_crt *) cert;
                return 0;
            }

            cert = cert->next;
        }
    }

    return ret;
}

static int mbedtls_pkcs7_data_or_hash_verify(const mbedtls_pkcs7 *pkcs7,
                                             const mbedtls_x509_crt *cert,
                                             const unsigned char *data,
                                             size_t datalen,
                                             const int is_data_hash,
                                             const int use_pkcs7_leaf)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *hash = NULL;
    const mbedtls_md_info_t *md_info;
    mbedtls_md_type_t md_alg;
    const mbedtls_pkcs7_signer_info *signer;
    mbedtls_x509_crt *leaf_cert = NULL;

    if (pkcs7->signed_data.no_of_signers == 0) {
        return MBEDTLS_ERR_PKCS7_INVALID_CERT;
    }

    ret = mbedtls_x509_oid_get_md_alg(&pkcs7->signed_data.digest_alg_identifiers, &md_alg);
    if (ret != 0) {
        return ret;
    }

    /* Ensure the MD alg from the PKCS#7 context and signature algorithm from
     * the certificate belong to the list of secure algorithms
     * (i.e. mbedtls_x509_crt_profile_default). */
    ret = mbedtls_x509_profile_check_md_alg(&mbedtls_x509_crt_profile_default, md_alg);
    if (ret != 0) {
        return MBEDTLS_ERR_PKCS7_INVALID_ALG;
    }
    ret = mbedtls_x509_profile_check_pk_alg(&mbedtls_x509_crt_profile_default, cert->sig_pk);
    if (ret != 0) {
        return MBEDTLS_ERR_PKCS7_INVALID_ALG;
    }

    md_info = mbedtls_md_info_from_type(md_alg);
    if (md_info == NULL) {
        return MBEDTLS_ERR_PKCS7_VERIFY_FAIL;
    }

    hash = mbedtls_calloc(mbedtls_md_get_size(md_info), 1);
    if (hash == NULL) {
        return MBEDTLS_ERR_PKCS7_ALLOC_FAILED;
    }

    /* BEGIN must free hash before jumping out */
    if (is_data_hash) {
        if (datalen != mbedtls_md_get_size(md_info)) {
            ret = MBEDTLS_ERR_PKCS7_VERIFY_FAIL;
        } else {
            memcpy(hash, data, datalen);
        }
    } else {
        ret = mbedtls_md(md_info, data, datalen, hash);
    }
    if (ret != 0) {
        mbedtls_free(hash);
        return MBEDTLS_ERR_PKCS7_VERIFY_FAIL;
    }

    /* assume failure */
    ret = MBEDTLS_ERR_PKCS7_VERIFY_FAIL;

    for (signer = &pkcs7->signed_data.signers; signer; signer = signer->next) {
        if (signer->sig.p == NULL || signer->sig.len == 0) {
            continue;
        }

        ret = pkcs7_get_leaf_cert(pkcs7, cert, signer, use_pkcs7_leaf, &leaf_cert);
        if (ret != 0) {
            continue;
        }

        if (use_pkcs7_leaf == 1) {
            ret = pkcs7_verify_chain(pkcs7->signed_data.certs, leaf_cert, cert);
            if (ret != 0) {
                continue;
            }
        }

        ret = mbedtls_pk_verify_ext(leaf_cert->sig_pk, &leaf_cert->pk, md_alg,
                                    hash, mbedtls_md_get_size(md_info),
                                    signer->sig.p, signer->sig.len);
        if (ret == 0) {
            break;
        }
    }

    mbedtls_free(hash);
    /* END must free hash before jumping out */
    return ret;
}

int mbedtls_pkcs7_signed_data_verify(const mbedtls_pkcs7 *pkcs7,
                                     const mbedtls_x509_crt *cert,
                                     const unsigned char *data,
                                     size_t datalen)
{
    if (data == NULL || pkcs7 == NULL || cert == NULL) {
        return MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA;
    }

    return mbedtls_pkcs7_data_or_hash_verify(pkcs7, cert, data, datalen, 0, 0);
}

int mbedtls_pkcs7_signed_hash_verify(const mbedtls_pkcs7 *pkcs7,
                                     const mbedtls_x509_crt *cert,
                                     const unsigned char *hash,
                                     size_t hashlen)
{
    if (hash == NULL || pkcs7 == NULL || cert == NULL) {
        return MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA;
    }

    return mbedtls_pkcs7_data_or_hash_verify(pkcs7, cert, hash, hashlen, 1, 0);
}

int mbedtls_pkcs7_signed_data_verify_ext(const mbedtls_pkcs7 *pkcs7,
                                         const mbedtls_x509_crt *trust_certs,
                                         const unsigned char *data,
                                         const size_t datalen,
                                         const int use_pkcs7_leaf)
{
    if (data == NULL || pkcs7 == NULL || trust_certs == NULL ||
        (use_pkcs7_leaf != 0 && use_pkcs7_leaf != 1)) {
        return MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA;
    }

    return mbedtls_pkcs7_data_or_hash_verify(pkcs7, trust_certs, data, datalen,
                                             0, use_pkcs7_leaf);
}

int mbedtls_pkcs7_signed_hash_verify_ext(const mbedtls_pkcs7 *pkcs7,
                                         const mbedtls_x509_crt *trust_certs,
                                         const unsigned char *hash,
                                         const size_t hashlen,
                                         const int use_pkcs7_leaf)
{
    if (hash == NULL || pkcs7 == NULL || trust_certs == NULL ||
        (use_pkcs7_leaf != 0 && use_pkcs7_leaf != 1)) {
        return MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA;
    }

    return mbedtls_pkcs7_data_or_hash_verify(pkcs7, trust_certs, hash, hashlen,
                                             1, use_pkcs7_leaf);
}

int mbedtls_pkcs7_get_cert_count(const mbedtls_pkcs7 *pkcs7)
{
    if (pkcs7 == NULL) {
        return MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA;
    }

    return pkcs7->signed_data.no_of_certs;
}

int mbedtls_pkcs7_get_certs(const mbedtls_pkcs7 *pkcs7,
                            mbedtls_x509_crt **out_certs)
{
    const mbedtls_pkcs7_cert *embedded_cert;
    mbedtls_x509_crt *cert_chain = NULL;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (pkcs7 == NULL || out_certs == NULL) {
        return MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA;
    }

    *out_certs = NULL;
    if (pkcs7->signed_data.no_of_certs == 0) {
        return MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA;
    }

    cert_chain = (mbedtls_x509_crt *) mbedtls_calloc(1, sizeof(mbedtls_x509_crt));
    if (cert_chain == NULL) {
        return MBEDTLS_ERR_PKCS7_ALLOC_FAILED;
    }

    mbedtls_x509_crt_init(cert_chain);

    for (embedded_cert = pkcs7->signed_data.certs; embedded_cert != NULL;
         embedded_cert = embedded_cert->next) {
        ret = mbedtls_x509_crt_parse_der(cert_chain, embedded_cert->cert.raw.p,
                                         embedded_cert->cert.raw.len);
        if (ret != 0) {
            mbedtls_x509_crt_free(cert_chain);
            mbedtls_free(cert_chain);
            return ret;
        }
    }

    *out_certs = cert_chain;

    return 0;
}

/*
 * Unallocate all pkcs7 data
 */
void mbedtls_pkcs7_free(mbedtls_pkcs7 *pkcs7)
{
    mbedtls_pkcs7_signer_info *signer_cur;
    mbedtls_pkcs7_signer_info *signer_prev;
    mbedtls_pkcs7_cert *cert_cur;
    mbedtls_pkcs7_cert *cert_prev;

    if (pkcs7 == NULL || pkcs7->raw.p == NULL) {
        return;
    }

    mbedtls_free(pkcs7->raw.p);

    cert_cur = pkcs7->signed_data.certs;
    while (cert_cur != NULL) {
        cert_prev = cert_cur;
        cert_cur = cert_cur->next;
        mbedtls_x509_crt_free(&cert_prev->cert);
        mbedtls_free(cert_prev);
    }

    pkcs7->signed_data.certs = NULL;

    mbedtls_x509_crl_free(&pkcs7->signed_data.crl);

    signer_cur = pkcs7->signed_data.signers.next;
    pkcs7_free_signer_info(&pkcs7->signed_data.signers);
    while (signer_cur != NULL) {
        signer_prev = signer_cur;
        signer_cur = signer_prev->next;
        pkcs7_free_signer_info(signer_prev);
        mbedtls_free(signer_prev);
    }

    mbedtls_platform_zeroize(pkcs7, sizeof(*pkcs7));
}

#endif
