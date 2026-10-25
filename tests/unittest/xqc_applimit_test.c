/*
 * Per-path app-limited marking (RFC 9002 Section 7.8,
 * draft-ietf-ccwg-bbr-06 Section 4.1.2.4). Each case drives real engine
 * passes on a client connection and reads the path's ctl_app_limited marker,
 * which BBR reads as "this path's samples are app-limited". The cases
 * use only code that predates the end-of-pass check, so the same file builds
 * with and without it.
 */

#include <CUnit/CUnit.h>
#include <string.h>

#include "xquic/xquic.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_timer.h"
#include "xqc_common_test.h"
#include "xqc_applimit_test.h"

/* xqc_path_create has no prototype in a header */
extern xqc_path_ctx_t *xqc_path_create(xqc_connection_t *conn,
    xqc_cid_t *scid, xqc_cid_t *dcid, uint64_t path_id);

static ssize_t
applimit_write_eagain(uint64_t path_id, const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user_data)
{
    return XQC_SOCKET_EAGAIN;
}

static ssize_t
applimit_write_mmsg(uint64_t path_id, const struct iovec *msg_iov,
    unsigned int vlen, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *user_data)
{
    return vlen;
}

static uint64_t
applimit_cwnd(xqc_send_ctl_t *ctl)
{
    return ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(ctl->ctl_cong);
}

/*
 * A client connection past its handshake whose initial path is idle, with
 * the marker cleared as an ACK clears it once the app-limited bubble is
 * delivered.
 */
static xqc_connection_t *
applimit_conn_create(const xqc_scheduler_callback_t *scheduler)
{
    xqc_conn_settings_t    settings;
    xqc_conn_ssl_config_t  ssl_config;
    xqc_engine_t          *engine;
    xqc_connection_t      *conn;
    xqc_send_ctl_t        *ctl;
    const xqc_cid_t       *cid;

    engine = test_create_engine();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);

    memset(&settings, 0, sizeof(settings));
    settings.proto_version = XQC_VERSION_V1;
    settings.cong_ctrl_callback = xqc_bbr_cb;
    settings.pacing_on = 1;
    if (scheduler != NULL) {
        settings.scheduler_callback = *scheduler;
    }

    memset(&ssl_config, 0, sizeof(ssl_config));
    cid = xqc_connect(engine, &settings, NULL, 0, "", 0, &ssl_config,
                      NULL, 0, "transport", NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(cid);
    conn = xqc_engine_conns_hash_find(engine, cid, 's');
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);

    conn->conn_state = XQC_CONN_STATE_ESTABED;
    conn->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_COMPLETED
                       | XQC_CONN_FLAG_HANDSHAKE_CONFIRMED;
    /* the peer's CID limit counts as reached, so the pass queues no
     * NEW_CONNECTION_ID packet, which it could not encrypt here */
    conn->remote_settings.active_connection_id_limit = 1;

    ctl = conn->conn_initial_path->path_send_ctl;
    /* keep the PTO of the ClientHello sent by xqc_connect out of the pass */
    xqc_timer_unset(&ctl->path_timer_manager, XQC_TIMER_LOSS_DETECTION);
    ctl->ctl_bytes_in_flight = 0;
    ctl->ctl_app_limited = 0;
    return conn;
}

/* a second ACTIVE path, STANDBY for the backup scheduler, idle */
static xqc_path_ctx_t *
applimit_add_standby_path(xqc_connection_t *conn)
{
    xqc_path_ctx_t  *path;
    xqc_cid_t        cid;

    conn->local_max_path_id = 1;
    CU_ASSERT_FATAL(xqc_generate_cid(conn->engine, NULL, &cid, 0) == XQC_OK);
    cid.path_id = 1;
    CU_ASSERT_FATAL(xqc_cid_set_add_path(&conn->scid_set, 1) == XQC_OK);
    CU_ASSERT_FATAL(xqc_cid_set_insert_cid(&conn->scid_set, &cid,
                                           XQC_CID_UNUSED, 2, 1) == XQC_OK);
    CU_ASSERT_FATAL(xqc_cid_set_add_path(&conn->dcid_set, 1) == XQC_OK);
    CU_ASSERT_FATAL(xqc_cid_set_insert_cid(&conn->dcid_set, &cid,
                                           XQC_CID_UNUSED, 2, 1) == XQC_OK);

    path = xqc_path_create(conn, NULL, NULL, 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(path);
    path->app_path_status = XQC_APP_PATH_STATUS_STANDBY;
    xqc_set_path_state(path, XQC_PATH_STATE_ACTIVE);
    path->path_send_ctl->ctl_app_limited = 0;
    return path;
}

/*
 * Ack-eliciting packet in the connection queue, where a stream write
 * leaves its data. A PING stands in for data: like STREAM it is
 * ack-eliciting and counts in flight.
 */
static xqc_packet_out_t *
applimit_queue_ping(xqc_connection_t *conn)
{
    xqc_packet_out_t *po;
    ssize_t           n;

    po = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT_PTR_NOT_NULL_FATAL(po);
    n = xqc_gen_ping_frame(po);
    CU_ASSERT_FATAL(n > 0);
    po->po_used_size += n;
    return po;
}

/*
 * One engine pass, entered as an application write enters it
 * (xqc_engine_conn_logic) or as a socket read or timer wakeup does
 * (xqc_engine_main_logic).
 */
static void
applimit_engine_pass(xqc_connection_t *conn, int via_main_logic)
{
    xqc_engine_t *engine = conn->engine;

    xqc_engine_remove_wakeup_queue(engine, conn);
    xqc_engine_add_active_queue(engine, conn);
    if (via_main_logic) {
        xqc_engine_main_logic(engine);

    } else {
        xqc_engine_conn_logic(engine, conn);
    }
    CU_ASSERT_FATAL(conn->conn_state != XQC_CONN_STATE_CLOSED);
}

/*
 * T1. Path 0 is cwnd-full; path 1, STANDBY under the backup scheduler, is
 * idle with room; a packet waits in the connection queue that the
 * scheduler gives to neither. Path 1 is app-limited, but the write-time
 * check needs an empty connection queue and leaves it unmarked (the old
 * FIXME in xqc_sample_check_app_limited). The end-of-pass check marks it,
 * and not path 0.
 */
static void
applimit_test_unfed_path(int via_main_logic)
{
    xqc_connection_t *conn = applimit_conn_create(&xqc_backup_scheduler_cb);
    xqc_path_ctx_t   *p0 = conn->conn_initial_path;
    xqc_path_ctx_t   *p1 = applimit_add_standby_path(conn);
    xqc_send_ctl_t   *c0 = p0->path_send_ctl;
    xqc_send_ctl_t   *c1 = p1->path_send_ctl;
    xqc_send_queue_t *sq = conn->conn_send_queue;
    xqc_packet_out_t *po;

    conn->enable_multipath = 1;
    /* equal measurements: the standby twin of path 0's class, so the
     * backup scheduler will not use path 1 while path 0 exists */
    CU_ASSERT_EQUAL_FATAL(xqc_path_get_perf_class(p1),
                          xqc_path_get_perf_class(p0) + 1);

    c0->ctl_bytes_in_flight = applimit_cwnd(c0);
    po = applimit_queue_ping(conn);

    xqc_conn_check_app_limit(conn);
    CU_ASSERT_EQUAL(c0->ctl_app_limited, 0);
    CU_ASSERT_EQUAL(c1->ctl_app_limited, 0);

    applimit_engine_pass(conn, via_main_logic);

    CU_ASSERT_PTR_EQUAL(sq->sndq_send_packets.next, &po->po_list);
    CU_ASSERT_EQUAL(p1->path_schedule_bytes, 0);
    CU_ASSERT_EQUAL(c1->ctl_bytes_in_flight, 0);
    CU_ASSERT(c1->ctl_app_limited > 0);
    CU_ASSERT_EQUAL(c0->ctl_app_limited, 0);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_applimit_unfed_path_conn_logic(void)
{
    applimit_test_unfed_path(0);
}

void
xqc_test_applimit_unfed_path_main_logic(void)
{
    applimit_test_unfed_path(1);
}

/*
 * T2. One path, nothing to send, marker cleared by an ACK, no application
 * write since: nothing re-marks the path at write time, so a PTO probe or
 * control packet sent next would carry an unflagged sample. One pass,
 * whatever drove it, marks the path. There is no multipath gate.
 */
static void
applimit_test_idle_path(int via_main_logic, int batch_send)
{
    xqc_connection_t *conn = applimit_conn_create(NULL);
    xqc_send_ctl_t   *ctl = conn->conn_initial_path->path_send_ctl;

    if (batch_send) {
        conn->engine->config->sendmmsg_on = 1;
        conn->engine->transport_cbs.write_mmsg_ex = applimit_write_mmsg;
        conn->transport_cbs.write_mmsg_ex = applimit_write_mmsg;
        CU_ASSERT_FATAL(xqc_engine_is_sendmmsg_on(conn->engine, conn));
    }
    applimit_engine_pass(conn, via_main_logic);

    CU_ASSERT_EQUAL(conn->enable_multipath, 0);
    CU_ASSERT(ctl->ctl_app_limited > 0);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_applimit_idle_path_conn_logic(void)
{
    applimit_test_idle_path(0, 0);
}

void
xqc_test_applimit_idle_path_main_logic(void)
{
    applimit_test_idle_path(1, 0);
}

void
xqc_test_applimit_idle_path_batch_send(void)
{
    applimit_test_idle_path(0, 1);
}

/*
 * T2, its effect: the mark is in place before the next pass sends, so the
 * probe that pass sends carries an app-limited sample.
 */
void
xqc_test_applimit_next_packet_flagged(void)
{
    xqc_connection_t *conn = applimit_conn_create(NULL);
    xqc_packet_out_t *po;
    ssize_t           n;

    applimit_engine_pass(conn, 0);

    /* Initial: the only packet type this client has keys for */
    po = xqc_write_new_packet(conn, XQC_PTYPE_INIT);
    CU_ASSERT_PTR_NOT_NULL_FATAL(po);
    n = xqc_gen_ping_frame(po);
    CU_ASSERT_FATAL(n > 0);
    po->po_used_size += n;

    applimit_engine_pass(conn, 0);

    CU_ASSERT(po->po_flag & XQC_POF_IN_FLIGHT);
    CU_ASSERT_EQUAL(po->po_is_app_limited, XQC_TRUE);

    xqc_engine_destroy(conn->engine);
}

/*
 * T3. A packet the pacer holds in the path's own buffer is unsent data, so
 * the path is not app-limited (RFC 9002 Section 7.8: "not pacing
 * limited"). The scheduler must admit it on the window alone and leave it
 * in the path buffer; the end-of-pass check depends on that.
 */
static void
applimit_test_pacing_held_packet(const xqc_scheduler_callback_t *scheduler)
{
    xqc_connection_t *conn = applimit_conn_create(scheduler);
    xqc_path_ctx_t   *path = conn->conn_initial_path;
    xqc_send_ctl_t   *ctl = path->path_send_ctl;

    ctl->ctl_pacing.bytes_budget = 0;
    applimit_queue_ping(conn);

    applimit_engine_pass(conn, 0);

    CU_ASSERT(!xqc_list_empty(&path->path_schedule_buf[XQC_SEND_TYPE_NORMAL]));
    CU_ASSERT(path->path_schedule_bytes > 0);
    CU_ASSERT_EQUAL(ctl->ctl_app_limited, 0);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_applimit_pacing_held_packet(void)
{
    applimit_test_pacing_held_packet(NULL);
}

/* T3. Less than one MSS of room left in the cwnd: not app-limited. */
void
xqc_test_applimit_cwnd_full(void)
{
    xqc_connection_t *conn = applimit_conn_create(NULL);
    xqc_send_ctl_t   *ctl = conn->conn_initial_path->path_send_ctl;

    ctl->ctl_bytes_in_flight = applimit_cwnd(ctl) - xqc_conn_get_mss(conn) + 1;

    applimit_engine_pass(conn, 0);

    CU_ASSERT_EQUAL(ctl->ctl_app_limited, 0);

    xqc_engine_destroy(conn->engine);
}

/*
 * T3. so_sndbuf below the cwnd caps the window packets are admitted
 * against (xqc_send_ctl_can_send): less than one MSS of room under it is
 * not app-limited, even with room left in the raw cwnd.
 */
void
xqc_test_applimit_sndbuf_full(void)
{
    xqc_connection_t *conn = applimit_conn_create(NULL);
    xqc_send_ctl_t   *ctl = conn->conn_initial_path->path_send_ctl;
    uint64_t          cwnd = applimit_cwnd(ctl);
    uint32_t          mss = xqc_conn_get_mss(conn);

    conn->conn_settings.so_sndbuf = cwnd / 2;
    CU_ASSERT_FATAL(conn->conn_settings.so_sndbuf > mss);
    ctl->ctl_bytes_in_flight = conn->conn_settings.so_sndbuf - mss + 1;
    CU_ASSERT_FATAL(ctl->ctl_bytes_in_flight + mss <= cwnd);

    applimit_engine_pass(conn, 0);

    CU_ASSERT_EQUAL(ctl->ctl_app_limited, 0);

    xqc_engine_destroy(conn->engine);
}

/*
 * T4. An ACK-only packet that a socket EAGAIN left in the path buffer is
 * not data to send: it is not ack-eliciting and path_schedule_bytes does
 * not count it, so the path is still marked.
 */
void
xqc_test_applimit_lingering_ack_only(void)
{
    static const unsigned char ack_frame[] = {0x02, 0x00, 0x00, 0x00, 0x00};
    xqc_connection_t *conn = applimit_conn_create(NULL);
    xqc_path_ctx_t   *path = conn->conn_initial_path;
    xqc_send_ctl_t   *ctl = path->path_send_ctl;
    xqc_packet_out_t *po;

    conn->transport_cbs.write_socket_ex = applimit_write_eagain;

    /* Initial keys are the ones this client has, so the packet encrypts
     * and only the socket refuses it */
    po = xqc_write_new_packet(conn, XQC_PTYPE_INIT);
    CU_ASSERT_PTR_NOT_NULL_FATAL(po);
    memcpy(po->po_buf + po->po_used_size, ack_frame, sizeof(ack_frame));
    po->po_used_size += sizeof(ack_frame);
    po->po_frame_types = XQC_FRAME_BIT_ACK;
    xqc_send_queue_move_to_high_pri(&po->po_list, conn->conn_send_queue);

    applimit_engine_pass(conn, 0);

    CU_ASSERT_PTR_EQUAL(
        path->path_schedule_buf[XQC_SEND_TYPE_NORMAL_HIGH_PRI].next,
        &po->po_list);
    CU_ASSERT_EQUAL(path->path_schedule_bytes, 0);
    CU_ASSERT(ctl->ctl_app_limited > 0);

    xqc_engine_destroy(conn->engine);
}

/*
 * T5. The marker is the delivered + inflight index that ACK processing
 * compares delivered against, or 1 when both are 0, as the write-time
 * check sets it; a later pass refreshes it.
 */
void
xqc_test_applimit_marker_value(void)
{
    xqc_connection_t *conn = applimit_conn_create(NULL);
    xqc_send_ctl_t   *ctl = conn->conn_initial_path->path_send_ctl;

    ctl->ctl_delivered = 0;
    applimit_engine_pass(conn, 0);
    CU_ASSERT_EQUAL(ctl->ctl_app_limited, 1);

    /* exactly one MSS of room left still counts */
    ctl->ctl_delivered = 50000;
    ctl->ctl_bytes_in_flight = applimit_cwnd(ctl) - xqc_conn_get_mss(conn);
    applimit_engine_pass(conn, 0);
    CU_ASSERT_EQUAL(ctl->ctl_app_limited, 50000 + ctl->ctl_bytes_in_flight);

    xqc_engine_destroy(conn->engine);
}

/*
 * T6. Marking on a pass leaves the pacer alone; a refill on every pass
 * would let the path burst past its pacing rate. The write-time check
 * still refills on its own mark.
 */
void
xqc_test_applimit_pacer_untouched(void)
{
    xqc_connection_t *conn = applimit_conn_create(NULL);
    xqc_send_ctl_t   *ctl = conn->conn_initial_path->path_send_ctl;
    xqc_pacing_t     *pacing = &ctl->ctl_pacing;

    pacing->bytes_budget = 1234;
    pacing->last_sent_time = 42;

    applimit_engine_pass(conn, 0);

    CU_ASSERT(ctl->ctl_app_limited > 0);
    CU_ASSERT_EQUAL(pacing->bytes_budget, 1234);
    CU_ASSERT_EQUAL(pacing->last_sent_time, 42);

    xqc_conn_check_app_limit(conn);
    CU_ASSERT_NOT_EQUAL(pacing->bytes_budget, 1234);
    CU_ASSERT_NOT_EQUAL(pacing->last_sent_time, 42);

    xqc_engine_destroy(conn->engine);
}
