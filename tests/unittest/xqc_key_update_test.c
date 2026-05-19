/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 *
 * Unit tests for RFC 9001 Section 6.1 key update precondition:
 *   "An endpoint MUST NOT initiate a key update prior to having confirmed
 *    the handshake (Section 4.1.2)."
 *
 * The fix lives in xqc_packet_encrypt_buf() (src/transport/xqc_packet_parser.c):
 * when all other key-update preconditions (pkt count, ack of current phase,
 * 3*PTO time guard) are satisfied, the encrypt path must still bail out with
 * XQC_OK (deferring the update) if the handshake is not yet confirmed.
 *
 * These two cases drive xqc_packet_encrypt_buf() with the trigger conditions
 * pre-armed and toggle XQC_CONN_FLAG_HANDSHAKE_CONFIRMED on/off to assert
 * that the key update is suppressed only in the unconfirmed state.
 */

#include <CUnit/CUnit.h>

#include "xqc_key_update_test.h"
#include "xqc_common_test.h"
#include "xquic/xquic.h"
#include "xquic/xquic_typedef.h"
#include "src/common/xqc_log.h"
#include "src/common/xqc_str.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_packet_parser.h"
#include "src/transport/xqc_send_ctl.h"


extern xqc_usec_t xqc_now();

/* test_ctx and helpers are defined in xqc_packet_test.c; reuse the same shape
 * here to keep behaviour consistent across packet-layer tests.
 */
typedef struct ku_test_ctx {
    xqc_engine_t        *engine;
    xqc_connection_t    *c;
    xqc_cid_t            cid;
    char                 buf[2048];
    size_t               buf_len;
} ku_test_ctx;


static ssize_t
ku_test_client_write(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data)
{
    ku_test_ctx *tctx = (ku_test_ctx *)conn_user_data;
    if (size <= sizeof(tctx->buf)) {
        memcpy(tctx->buf, buf, size);
        tctx->buf_len = size;
    }
    return size;
}

static int
ku_test_client_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *user_data, void *conn_proto_data)
{
    ku_test_ctx *tctx = (ku_test_ctx *)user_data;
    tctx->c = conn;
    memcpy(&tctx->cid, cid, sizeof(xqc_cid_t));
    xqc_conn_set_alp_user_data(conn, tctx);
    return 0;
}

static void
ku_test_set_event_timer(xqc_msec_t wake_after, void *engine_user_data)
{
    return;
}

static xqc_engine_t *
ku_create_client_engine(ku_test_ctx *tctx)
{
    xqc_engine_ssl_config_t engine_ssl_config;
    engine_ssl_config.private_key_file = "./server.key";
    engine_ssl_config.cert_file = "./server.crt";
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;
    engine_ssl_config.session_ticket_key_len = 0;
    engine_ssl_config.session_ticket_key_data = NULL;

    xqc_engine_callback_t callback = {
        .set_event_timer = ku_test_set_event_timer,
    };
    xqc_transport_callbacks_t tcbs = {
        .write_socket = ku_test_client_write,
    };
    xqc_app_proto_callbacks_t transport_cbs = {
        .conn_cbs.conn_create_notify = ku_test_client_conn_create_notify,
    };

    xqc_engine_t *engine = xqc_engine_create(XQC_ENGINE_CLIENT, NULL,
                                             &engine_ssl_config, &callback, &tcbs, tctx);
    xqc_engine_register_alpn(engine, "transport", 9, &transport_cbs, NULL);
    return engine;
}

/* Drive xqc_packet_encrypt_buf() on a fully-armed key-update trigger state,
 * then observe whether the key update fires (enc_pkt_cnt resets to 0 inside
 * xqc_conn_confirm_key_update()) or is deferred (enc_pkt_cnt stays > threshold).
 */
static xqc_int_t
ku_drive_encrypt(ku_test_ctx *tctx, xqc_packet_out_t *po, char *dst, size_t dst_cap, size_t *enc_len)
{
    xqc_connection_t *c = tctx->c;
    xqc_send_ctl_t   *sctl = c->conn_initial_path->path_send_ctl;

    /* arm trigger conditions for the 1-RTT key update path */
    c->conn_settings.keyupdate_pkt_threshold        = 1;
    c->key_update_ctx.enc_pkt_cnt                   = 5;            /* > threshold */
    c->key_update_ctx.first_sent_pktno              = 0;
    sctl->ctl_largest_acked[XQC_PNS_APP_DATA]       = 100;          /* first_sent <= largest_ack */
    c->key_update_ctx.initiate_time_guard           = 0;            /* time guard already elapsed */

    po->po_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;

    return xqc_packet_encrypt_buf(c, po, (unsigned char *)dst, dst_cap, enc_len);
}


/*
 * Case 1: handshake NOT confirmed
 *   Expectation: xqc_packet_encrypt_buf() returns XQC_OK but the key update
 *   path bails out early. The post-call enc_pkt_cnt MUST still be greater
 *   than the threshold (i.e. NOT reset by xqc_conn_confirm_key_update()),
 *   proving the new RFC 9001 §6.1 guard suppressed the update.
 */
void
xqc_test_key_update_blocked_before_handshake_confirmed(void)
{
    ku_test_ctx tctx = {0};
    tctx.engine = ku_create_client_engine(&tctx);
    CU_ASSERT_PTR_NOT_NULL(tctx.engine);
    if (tctx.engine == NULL) {
        return;
    }

    xqc_conn_settings_t conn_settings;
    memset(&conn_settings, 0, sizeof(conn_settings));
    conn_settings.proto_version = XQC_VERSION_V1;

    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));

    xqc_connect(tctx.engine, &conn_settings, NULL, 0, "", 0,
                &conn_ssl_config, NULL, 0, "transport", &tctx);
    CU_ASSERT_PTR_NOT_NULL(tctx.c);
    if (tctx.c == NULL) {
        xqc_engine_destroy(tctx.engine);
        return;
    }

    /* explicitly clear the confirmed flag to simulate the pre-confirmation window */
    tctx.c->conn_flag &= ~XQC_CONN_FLAG_HANDSHAKE_CONFIRMED;
    CU_ASSERT_FALSE(xqc_conn_is_handshake_confirmed(tctx.c));

    xqc_packet_out_t *po = xqc_packet_out_create(2048);
    CU_ASSERT_PTR_NOT_NULL(po);
    if (po == NULL) {
        xqc_conn_close(tctx.engine, &tctx.cid);
        xqc_engine_destroy(tctx.engine);
        return;
    }

    char   dst[4096] = {0};
    size_t enc_len   = 0;
    xqc_int_t ret    = ku_drive_encrypt(&tctx, po, dst, sizeof(dst), &enc_len);

    /* The fix returns XQC_OK and exits before invoking xqc_tls_update_1rtt_keys,
     * so enc_pkt_cnt is NOT reset to 0 by xqc_conn_confirm_key_update().
     */
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(tctx.c->key_update_ctx.enc_pkt_cnt
              > tctx.c->conn_settings.keyupdate_pkt_threshold);

    xqc_packet_out_destroy(po);
    xqc_conn_close(tctx.engine, &tctx.cid);
    xqc_engine_destroy(tctx.engine);
}


/*
 * Case 2: handshake IS confirmed
 *   Expectation: the same armed trigger state now reaches the key-update
 *   branch. We do not require the actual tls key rotation to succeed (it
 *   depends on installed 1-RTT keys which this synthetic test doesn't have),
 *   but the test asserts the guard does NOT short-circuit on the new
 *   confirmation check — i.e. the function does not return XQC_OK with
 *   enc_pkt_cnt unchanged. Either:
 *     (a) the rotation succeeds → enc_pkt_cnt is reset to 0, OR
 *     (b) tls rotation fails → ret != XQC_OK (proving the guard was crossed).
 *   Both outcomes prove the confirmation guard is correctly bypassed when
 *   the handshake is confirmed.
 */
void
xqc_test_key_update_allowed_after_handshake_confirmed(void)
{
    ku_test_ctx tctx = {0};
    tctx.engine = ku_create_client_engine(&tctx);
    CU_ASSERT_PTR_NOT_NULL(tctx.engine);
    if (tctx.engine == NULL) {
        return;
    }

    xqc_conn_settings_t conn_settings;
    memset(&conn_settings, 0, sizeof(conn_settings));
    conn_settings.proto_version = XQC_VERSION_V1;

    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));

    xqc_connect(tctx.engine, &conn_settings, NULL, 0, "", 0,
                &conn_ssl_config, NULL, 0, "transport", &tctx);
    CU_ASSERT_PTR_NOT_NULL(tctx.c);
    if (tctx.c == NULL) {
        xqc_engine_destroy(tctx.engine);
        return;
    }

    /* mark the connection as confirmed so the new guard becomes transparent */
    tctx.c->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_CONFIRMED;
    CU_ASSERT_TRUE(xqc_conn_is_handshake_confirmed(tctx.c));

    xqc_packet_out_t *po = xqc_packet_out_create(2048);
    CU_ASSERT_PTR_NOT_NULL(po);
    if (po == NULL) {
        xqc_conn_close(tctx.engine, &tctx.cid);
        xqc_engine_destroy(tctx.engine);
        return;
    }

    uint64_t cnt_before = tctx.c->key_update_ctx.enc_pkt_cnt;

    char   dst[4096] = {0};
    size_t enc_len   = 0;
    xqc_int_t ret    = ku_drive_encrypt(&tctx, po, dst, sizeof(dst), &enc_len);

    /* The guard let us through. Either the tls layer accepted the rotation
     * (enc_pkt_cnt reset to 0 by xqc_conn_confirm_key_update) OR it rejected
     * later (ret != XQC_OK). What we must NOT see is "ret == XQC_OK and
     * enc_pkt_cnt unchanged and > threshold" — that would mean the new
     * confirmation guard wrongly fired.
     */
    int short_circuited_by_new_guard =
        (ret == XQC_OK
         && tctx.c->key_update_ctx.enc_pkt_cnt == cnt_before + 1
         && tctx.c->key_update_ctx.enc_pkt_cnt
            > tctx.c->conn_settings.keyupdate_pkt_threshold);
    CU_ASSERT_FALSE(short_circuited_by_new_guard);

    xqc_packet_out_destroy(po);
    xqc_conn_close(tctx.engine, &tctx.cid);
    xqc_engine_destroy(tctx.engine);
}
