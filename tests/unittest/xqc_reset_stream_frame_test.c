/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_reset_stream_frame_test.h"
#include "xqc_common_test.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_stream.h"
#include "xquic/xqc_errno.h"

/*
 * RESET_STREAM frame (RFC 9000 19.4):
 *   type            : 0x04
 *   stream id       : varint
 *   app error code  : varint
 *   final size      : varint
 *
 * The frames below reset stream id 0 (client-initiated bidirectional) with
 * application error code 0x11 and final size 0x20. All fields use single-byte
 * varints; varint encoding itself is covered elsewhere.
 */
#define XQC_TEST_RESET_ERR_CODE  0x11
#define XQC_TEST_RESET_FINAL_SZ  0x20

static unsigned char XQC_TEST_RESET_STREAM_FRAME[] = {
    0x04,
    0x00,
    XQC_TEST_RESET_ERR_CODE,
    XQC_TEST_RESET_FINAL_SZ
};


/* state observed by the closing callback, so ordering can be asserted */
typedef struct xqc_reset_closing_obs_s {
    xqc_int_t       call_cnt;
    xqc_int_t       err;
    xqc_int_t       send_state;
    xqc_int_t       recv_state;
    xqc_flag_t      ready_to_write;
    uint64_t        peer_reset_time;
    xqc_bool_t      frames_tailq_empty;
    xqc_bool_t      destroy_in_callback;
    xqc_stream_id_t stream_id;
} xqc_reset_closing_obs_t;


static void
xqc_test_reset_closing_notify(xqc_stream_t *stream, xqc_int_t err,
    void *strm_user_data)
{
    xqc_reset_closing_obs_t *obs = (xqc_reset_closing_obs_t *)strm_user_data;

    obs->call_cnt++;
    obs->err = err;
    obs->stream_id = stream->stream_id;
    obs->send_state = stream->stream_state_send;
    obs->recv_state = stream->stream_state_recv;
    obs->ready_to_write =
        stream->stream_flag & XQC_STREAM_FLAG_READY_TO_WRITE;
    obs->peer_reset_time = stream->stream_stats.peer_reset_time;
    obs->frames_tailq_empty =
        xqc_list_empty(&stream->stream_data_in.frames_tailq);

    /*
     * Emulate the reentrant application callback that reaches the engine and
     * lets the STREAM_CLOSE timer reap this stream: the frame handler must not
     * touch `stream` after this callback returns.
     */
    if (obs->destroy_in_callback) {
        xqc_destroy_stream(stream);
    }
}


/*
 * Static storage keeps the injected callback table valid for the whole
 * lifetime of the connection, including the stream teardown that runs
 * inside xqc_engine_destroy().
 */
static xqc_stream_callbacks_t xqc_test_reset_stream_cbs;


static xqc_stream_t *
xqc_test_reset_stream_setup(xqc_connection_t **conn, xqc_packet_in_t *pi,
    xqc_reset_closing_obs_t *obs)
{
    xqc_stream_t *stream;

    *conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(*conn);

    stream = xqc_stream_create_with_direction(*conn, XQC_STREAM_BIDI, NULL);
    CU_ASSERT_PTR_NOT_NULL_FATAL(stream);
    CU_ASSERT(stream->stream_id == 0);

    memset(&xqc_test_reset_stream_cbs, 0,
           sizeof(xqc_test_reset_stream_cbs));
    xqc_test_reset_stream_cbs.stream_closing_notify =
        xqc_test_reset_closing_notify;
    stream->stream_if = &xqc_test_reset_stream_cbs;
    stream->user_data = obs;

    memset(pi, 0, sizeof(*pi));
    pi->pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    pi->pos = XQC_TEST_RESET_STREAM_FRAME;
    pi->last = pi->pos + sizeof(XQC_TEST_RESET_STREAM_FRAME);

    return stream;
}


/*
 * Happy path: a peer RESET_STREAM completes both directions of the local
 * reset handling, and the closing notify observes the finished state.
 *
 * The assertions on the observed state pin the callback to the end of
 * xqc_process_reset_stream_frame: moving it back before the reset handling
 * would leave the send/recv state un-updated at notify time.
 */
void
xqc_test_reset_stream_frame_notify_last()
{
    xqc_connection_t        *conn;
    xqc_packet_in_t          pi;
    xqc_reset_closing_obs_t  obs;
    xqc_stream_t            *stream;
    uint64_t                 fc_recved;
    uint64_t                 fc_read;
    xqc_int_t                ret;

    memset(&obs, 0, sizeof(obs));
    stream = xqc_test_reset_stream_setup(&conn, &pi, &obs);

    /* a locally initiated stream starts out writable */
    CU_ASSERT((stream->stream_flag & XQC_STREAM_FLAG_READY_TO_WRITE) != 0);

    fc_recved = conn->conn_flow_ctl.fc_data_recved;
    fc_read = conn->conn_flow_ctl.fc_data_read;

    ret = xqc_process_reset_stream_frame(conn, &pi);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT((pi.pi_frame_types & XQC_FRAME_BIT_RESET_STREAM) != 0);

    /* the application was notified exactly once, with the peer error code */
    CU_ASSERT(obs.call_cnt == 1);
    CU_ASSERT(obs.err == XQC_TEST_RESET_ERR_CODE);
    CU_ASSERT(obs.stream_id == 0);

    /*
     * RFC 9000 3.1/3.2: both directions are already settled when the
     * application learns about the reset.
     */
    CU_ASSERT(obs.send_state == XQC_SEND_STREAM_ST_RESET_SENT);
    CU_ASSERT(obs.recv_state == XQC_RECV_STREAM_ST_RESET_RECVD);
    CU_ASSERT(obs.ready_to_write == 0);
    CU_ASSERT(obs.peer_reset_time != 0);
    CU_ASSERT(obs.frames_tailq_empty == XQC_TRUE);

    /* the surviving stream keeps the settled state */
    CU_ASSERT(stream->stream_err == XQC_TEST_RESET_ERR_CODE);
    CU_ASSERT(stream->stream_state_send == XQC_SEND_STREAM_ST_RESET_SENT);
    CU_ASSERT(stream->stream_state_recv == XQC_RECV_STREAM_ST_RESET_RECVD);
    CU_ASSERT((stream->stream_flag & XQC_STREAM_FLAG_READY_TO_WRITE) == 0);
    CU_ASSERT(stream->stream_data_in.buffered_frame_count == 0);

    /* RFC 9000 4.5: the final size is accounted for on the connection */
    CU_ASSERT(conn->conn_flow_ctl.fc_data_recved
              == fc_recved + XQC_TEST_RESET_FINAL_SZ);
    CU_ASSERT(conn->conn_flow_ctl.fc_data_read
              == fc_read + XQC_TEST_RESET_FINAL_SZ);

    xqc_engine_destroy(conn->engine);
}


/*
 * Abnormal path: the closing callback destroys the stream, which is what a
 * reentrant application callback can trigger through a nested engine pass.
 *
 * The frame handler must have finished every access to the stream before the
 * notify, so processing still reports success and the connection-level reset
 * accounting stays intact after the stream is gone.
 */
void
xqc_test_reset_stream_frame_closing_destroys_stream()
{
    xqc_connection_t        *conn;
    xqc_packet_in_t          pi;
    xqc_reset_closing_obs_t  obs;
    uint64_t                 fc_recved;
    uint64_t                 fc_read;
    xqc_int_t                ret;

    memset(&obs, 0, sizeof(obs));
    obs.destroy_in_callback = XQC_TRUE;
    xqc_test_reset_stream_setup(&conn, &pi, &obs);

    fc_recved = conn->conn_flow_ctl.fc_data_recved;
    fc_read = conn->conn_flow_ctl.fc_data_read;

    ret = xqc_process_reset_stream_frame(conn, &pi);
    CU_ASSERT(ret == XQC_OK);

    CU_ASSERT(obs.call_cnt == 1);

    /* the reset was fully handled before the stream was destroyed */
    CU_ASSERT(obs.send_state == XQC_SEND_STREAM_ST_RESET_SENT);
    CU_ASSERT(obs.recv_state == XQC_RECV_STREAM_ST_RESET_RECVD);
    CU_ASSERT(obs.ready_to_write == 0);
    CU_ASSERT(conn->conn_flow_ctl.fc_data_recved
              == fc_recved + XQC_TEST_RESET_FINAL_SZ);
    CU_ASSERT(conn->conn_flow_ctl.fc_data_read
              == fc_read + XQC_TEST_RESET_FINAL_SZ);

    /* the destroyed stream is no longer reachable */
    CU_ASSERT_PTR_NULL(xqc_find_stream_by_id(0, conn->streams_hash));

    xqc_engine_destroy(conn->engine);
}


/*
 * A retransmitted RESET_STREAM for an already reset stream keeps notifying
 * the application, but must not double-count the final size or reopen the
 * settled send/recv state.
 */
void
xqc_test_reset_stream_frame_duplicate()
{
    xqc_connection_t        *conn;
    xqc_packet_in_t          pi;
    xqc_reset_closing_obs_t  obs;
    xqc_stream_t            *stream;
    uint64_t                 fc_recved;
    uint64_t                 fc_read;
    xqc_int_t                ret;

    memset(&obs, 0, sizeof(obs));
    stream = xqc_test_reset_stream_setup(&conn, &pi, &obs);

    ret = xqc_process_reset_stream_frame(conn, &pi);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(obs.call_cnt == 1);

    fc_recved = conn->conn_flow_ctl.fc_data_recved;
    fc_read = conn->conn_flow_ctl.fc_data_read;

    /* replay the same frame */
    pi.pos = XQC_TEST_RESET_STREAM_FRAME;
    pi.last = pi.pos + sizeof(XQC_TEST_RESET_STREAM_FRAME);

    ret = xqc_process_reset_stream_frame(conn, &pi);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(obs.call_cnt == 2);

    CU_ASSERT(conn->conn_flow_ctl.fc_data_recved == fc_recved);
    CU_ASSERT(conn->conn_flow_ctl.fc_data_read == fc_read);
    CU_ASSERT(stream->stream_state_send == XQC_SEND_STREAM_ST_RESET_SENT);
    CU_ASSERT(stream->stream_state_recv == XQC_RECV_STREAM_ST_RESET_RECVD);

    /* Keep the baseline behavior: a late ordinary reset is ignored. */
    unsigned char late_reset[] = {
        0x04, 0x00, XQC_TEST_RESET_ERR_CODE + 1,
        XQC_TEST_RESET_FINAL_SZ + 1,
    };
    pi.pos = late_reset;
    pi.last = pi.pos + sizeof(late_reset);
    CU_ASSERT(xqc_process_reset_stream_frame(conn, &pi) == XQC_OK);
    CU_ASSERT(obs.call_cnt == 3);
    CU_ASSERT(conn->conn_flow_ctl.fc_data_recved == fc_recved);
    CU_ASSERT(conn->conn_flow_ctl.fc_data_read == fc_read);

    xqc_engine_destroy(conn->engine);
}
