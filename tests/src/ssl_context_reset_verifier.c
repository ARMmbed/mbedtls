/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * The following function was automatically generated through the script
 * ./tests/scripts/generate_ssl_session_reset_check.py.
 */

#include <test/ssl_helpers.h>
#include <test/ssl_helpers_internal.h>
#include "mbedtls/psa_util.h"
#include <test/macros.h>

#include <limits.h>

#if defined(MBEDTLS_SSL_TLS_C)

int mbedtls_test_ssl_check_context_after_session_reset(const mbedtls_ssl_context *before,
                                                       const mbedtls_ssl_context *after)
{
    mbedtls_ssl_context initial;
    int ret = -1;

    /* Create a freshly initialized SSL context*/
    memset(&initial, 0, sizeof(initial));
    mbedtls_ssl_init(&initial);
    TEST_EQUAL(mbedtls_ssl_setup(&initial, after->conf), 0);

    /* *INDENT-OFF* */
    TEST_ASSERT(before->conf == after->conf);
    TEST_ASSERT(after->state == initial.state);
    TEST_EQUAL((after->flags & ~(MBEDTLS_SSL_CONTEXT_FLAGS_KEEP_AT_SESSION)), initial.flags);
    TEST_EQUAL((before->flags & MBEDTLS_SSL_CONTEXT_FLAGS_KEEP_AT_SESSION), (after->flags & MBEDTLS_SSL_CONTEXT_FLAGS_KEEP_AT_SESSION));
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    TEST_ASSERT(after->renego_status == initial.renego_status);
#endif
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    TEST_ASSERT(after->renego_records_seen == initial.renego_records_seen);
#endif
    TEST_ASSERT(after->tls_version == after->conf->max_tls_version);
#if defined(MBEDTLS_SSL_EARLY_DATA) && defined(MBEDTLS_SSL_CLI_C)
    TEST_ASSERT(after->early_data_state == initial.early_data_state);
#endif
    TEST_ASSERT(after->badmac_seen == initial.badmac_seen);
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    TEST_ASSERT(before->f_vrfy == after->f_vrfy);
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    TEST_ASSERT(before->p_vrfy == after->p_vrfy);
#endif
    TEST_ASSERT(before->f_send == after->f_send);
    TEST_ASSERT(before->f_recv == after->f_recv);
    TEST_ASSERT(before->f_recv_timeout == after->f_recv_timeout);
    TEST_ASSERT(before->p_bio == after->p_bio);
    TEST_ASSERT(after->session_in == initial.session_in);
    TEST_ASSERT(after->session_out == initial.session_out);
    TEST_ASSERT(after->session == initial.session);
    TEST_ASSERT(after->session_negotiate != NULL);
    TEST_ASSERT(after->handshake != NULL);
    TEST_ASSERT(after->transform_in == initial.transform_in);
    TEST_ASSERT(after->transform_out == initial.transform_out);
    TEST_ASSERT(after->transform == initial.transform);
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    TEST_ASSERT(after->transform_negotiate != NULL);
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    TEST_ASSERT(after->transform_application == initial.transform_application);
#endif
    TEST_ASSERT(before->p_timer == after->p_timer);
    TEST_ASSERT(before->f_set_timer == after->f_set_timer);
    TEST_ASSERT(before->f_get_timer == after->f_get_timer);
    TEST_ASSERT(after->in_buf != NULL);
    TEST_ASSERT(after->in_ctr != NULL);
    TEST_ASSERT(after->in_hdr != NULL);
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    TEST_ASSERT(after->in_cid != NULL);
#endif
    TEST_ASSERT(after->in_len != NULL);
    TEST_ASSERT(after->in_iv != NULL);
    TEST_ASSERT(after->in_msg != NULL);
    TEST_ASSERT(after->in_offt == initial.in_offt);
    TEST_ASSERT(after->in_msgtype == initial.in_msgtype);
    TEST_ASSERT(after->in_msglen == initial.in_msglen);
    TEST_ASSERT(after->in_left == initial.in_left);
#if defined(MBEDTLS_SSL_HAVE_BUFFER_LEN_FIELDS)
    #if defined(MBEDTLS_SSL_RUNTIME_CONTENT_LEN)
    TEST_ASSERT(after->in_buf_len == MBEDTLS_SSL_IN_BUFFER_LEN -
                (MBEDTLS_SSL_IN_CONTENT_LEN - after->in_content_len));
    #else
    TEST_ASSERT(after->in_buf_len == MBEDTLS_SSL_IN_BUFFER_LEN);
    #endif
#endif
#if defined(MBEDTLS_SSL_RUNTIME_CONTENT_LEN)
    TEST_EQUAL(before->in_content_len, after->in_content_len);
#endif
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    TEST_ASSERT(after->in_epoch == initial.in_epoch);
#endif
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    TEST_ASSERT(after->next_record_offset == initial.next_record_offset);
#endif
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    TEST_ASSERT(after->in_window_top == initial.in_window_top);
#endif
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    TEST_ASSERT(after->in_window == initial.in_window);
#endif
    TEST_ASSERT(after->in_hslen == initial.in_hslen);
    TEST_ASSERT(after->in_hsfraglen == initial.in_hsfraglen);
    TEST_ASSERT(after->nb_zero == initial.nb_zero);
    TEST_ASSERT(after->keep_current_message == initial.keep_current_message);
    TEST_ASSERT(after->in_fatal_alert_recv == initial.in_fatal_alert_recv);
    TEST_ASSERT(after->in_fatal_alert_type == initial.in_fatal_alert_type);
    TEST_ASSERT(after->send_alert == initial.send_alert);
    TEST_ASSERT(after->alert_type == initial.alert_type);
    TEST_ASSERT(after->alert_reason == initial.alert_reason);
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    TEST_EQUAL(before->disable_datagram_packing, after->disable_datagram_packing);
#endif
#if defined(MBEDTLS_SSL_EARLY_DATA)

#if defined(MBEDTLS_SSL_SRV_C)
    TEST_ASSERT(after->discard_early_data_record == initial.discard_early_data_record);
#endif
#endif
#if defined(MBEDTLS_SSL_EARLY_DATA)
    TEST_ASSERT(after->total_early_data_size == initial.total_early_data_size);
#endif
    TEST_ASSERT(after->out_buf != NULL);
    TEST_ASSERT(after->out_ctr != NULL);
    TEST_ASSERT(after->out_hdr != NULL);
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    TEST_ASSERT(after->out_cid != NULL);
#endif
    TEST_ASSERT(after->out_len != NULL);
    TEST_ASSERT(after->out_iv != NULL);
    TEST_ASSERT(after->out_msg != NULL);
    TEST_ASSERT(after->out_msgtype == initial.out_msgtype);
    TEST_ASSERT(after->out_msglen == initial.out_msglen);
    TEST_ASSERT(after->out_left == initial.out_left);
#if defined(MBEDTLS_SSL_HAVE_BUFFER_LEN_FIELDS)
    #if defined(MBEDTLS_SSL_RUNTIME_CONTENT_LEN)
    TEST_ASSERT(after->out_buf_len == MBEDTLS_SSL_OUT_BUFFER_LEN -
                (MBEDTLS_SSL_OUT_CONTENT_LEN - after->out_content_len));
    #else
    TEST_ASSERT(after->out_buf_len == MBEDTLS_SSL_OUT_BUFFER_LEN);
    #endif
#endif
#if defined(MBEDTLS_SSL_RUNTIME_CONTENT_LEN)
    TEST_EQUAL(before->out_content_len, after->out_content_len);
#endif
    TEST_MEMORY_COMPARE(after->cur_out_ctr, sizeof(after->cur_out_ctr), initial.cur_out_ctr, sizeof(initial.cur_out_ctr));
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    TEST_EQUAL(before->mtu, after->mtu);
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    TEST_ASSERT(before->hostname == after->hostname);
#endif
#if defined(MBEDTLS_SSL_ALPN)
    TEST_ASSERT(after->alpn_chosen == initial.alpn_chosen);
#endif
#if defined(MBEDTLS_SSL_DTLS_SRTP)
    TEST_MEMORY_COMPARE(&(after->dtls_srtp_info), sizeof(after->dtls_srtp_info), &(initial.dtls_srtp_info), sizeof(initial.dtls_srtp_info));
#endif
#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY) && defined(MBEDTLS_SSL_SRV_C)
    TEST_ASSERT(after->cli_id == initial.cli_id);
#endif
#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY) && defined(MBEDTLS_SSL_SRV_C)
    TEST_ASSERT(after->cli_id_len == initial.cli_id_len);
#endif
    TEST_ASSERT(after->secure_renegotiation == initial.secure_renegotiation);
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    TEST_ASSERT(after->verify_data_len == initial.verify_data_len);
#endif
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    TEST_MEMORY_COMPARE(after->own_verify_data, sizeof(after->own_verify_data), initial.own_verify_data, sizeof(initial.own_verify_data));
#endif
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    TEST_MEMORY_COMPARE(after->peer_verify_data, sizeof(after->peer_verify_data), initial.peer_verify_data, sizeof(initial.peer_verify_data));
#endif
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    TEST_MEMORY_COMPARE(before->own_cid, sizeof(before->own_cid), after->own_cid, sizeof(after->own_cid));
#endif
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    TEST_EQUAL(before->own_cid_len, after->own_cid_len);
#endif
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    TEST_EQUAL(before->negotiate_cid, after->negotiate_cid);
#endif
    TEST_ASSERT(before->f_export_keys == after->f_export_keys);
    TEST_ASSERT(before->p_export_keys == after->p_export_keys);
    TEST_ASSERT(before->user_data.n == after->user_data.n);
    /* unused is ignored */
    /* *INDENT-ON* */

    ret = 0;

exit:
    mbedtls_ssl_free(&initial);

    return ret;
}

#endif /* MBEDTLS_SSL_TLS_C */
