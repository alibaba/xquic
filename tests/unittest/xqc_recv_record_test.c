/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_recv_record_test.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_recv_record.h"
#include "src/transport/xqc_recv_timestamps_info.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_timer.h"
#include "xqc_common_test.h"
#include <string.h>
#include <CUnit/CUnit.h>
#include <stdio.h>

void
xqc_test_recv_record()
{
    xqc_list_head_t *pos;
    xqc_pktno_range_node_t *pnode;
    xqc_recv_record_t record;
    memset(&record, 0, sizeof(xqc_recv_record_t));
    xqc_init_list_head(&record.list_head);

    xqc_recv_record_add(&record, 0);
    xqc_recv_record_add(&record, 1);
    xqc_recv_record_add(&record, 10);
    xqc_recv_record_add(&record, 2);

    xqc_list_for_each(pos, &record.list_head) {
        pnode = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
        //printf("low:%llu, high=%llu\n", pnode->pktno_range.low, pnode->pktno_range.high);
    }

    /* printf("largest=%llu\n", xqc_recv_record_largest(&record)); */
    CU_ASSERT(10 == xqc_recv_record_largest(&record));


    xqc_recv_record_del(&record, 5);
    xqc_list_for_each(pos, &record.list_head) {
        pnode = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
        //printf("low:%llu, high=%llu\n", pnode->pktno_range.low, pnode->pktno_range.high);
    }

    xqc_recv_record_destroy(&record);
}


/*
 * The receive timestamps ring flags the slots whose packet opens a new
 * range in a 64-bit word, so the flags of slots 31 and above must be
 * shifted as 64-bit values. Each range costs two bytes in the size
 * estimate of the ACK frame's timestamps.
 */
void
xqc_test_recv_timestamps_range_flag()
{
    const uint64_t  gapped = 40, consecutive = 10;
    const uint64_t  ranges = ((1ULL << gapped) - 1) & ~1ULL;
    uint64_t        pn;

    xqc_recv_timestamps_info_t *ts_info = xqc_recv_timestamps_info_create();
    CU_ASSERT_PTR_NOT_NULL_FATAL(ts_info);

    /* every other packet number: each packet after the first opens a range */
    for (pn = 0; pn < 2 * gapped; pn += 2) {
        xqc_recv_timestamps_info_add_pkt(ts_info, pn, 1000 * pn);
    }
    CU_ASSERT(ts_info->new_range_flag == ranges);
    CU_ASSERT(xqc_recv_timestamps_info_need_bytes_estimate(ts_info)
              == 1 + gapped * 2 + 4 + (gapped - 1));

    /* consecutive packets clear only their own slots */
    for (pn = 2 * gapped - 1; pn < 2 * gapped - 1 + consecutive; pn++) {
        xqc_recv_timestamps_info_add_pkt(ts_info, pn, 1000 * pn);
    }
    CU_ASSERT(ts_info->new_range_flag == ranges);
    CU_ASSERT(xqc_recv_timestamps_info_length(ts_info)
              == gapped + consecutive);

    /* abnormal: a reordered packet is not recorded */
    xqc_recv_timestamps_info_add_pkt(ts_info, 1, 1000);
    CU_ASSERT(ts_info->new_range_flag == ranges);
    CU_ASSERT(xqc_recv_timestamps_info_length(ts_info)
              == gapped + consecutive);

    xqc_recv_timestamps_info_destroy(ts_info);
}


/*
 * RFC 9000 Section 18.2: max_ack_delay "SHOULD include the receiver's
 * expected delays in alarms firing". The delayed ACK timer is armed one
 * timer granularity (RFC 9002 Section 6.1.2) before the advertised
 * max_ack_delay, so that it can fire that late and still acknowledge
 * within it.
 */
static xqc_usec_t
xqc_test_ack_timer_expiry(xqc_connection_t *conn, xqc_usec_t now)
{
    xqc_path_ctx_t *path = conn->conn_initial_path;
    xqc_send_ctl_t *send_ctl = path->path_send_ctl;
    xqc_timer_t *timer =
        &send_ctl->path_timer_manager.timer[XQC_TIMER_ACK_01RTT];

    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT;
    xqc_timer_unset(&send_ctl->path_timer_manager, XQC_TIMER_ACK_01RTT);

    /* one ack-eliciting packet, below ack_frequency: the timer delays it */
    send_ctl->ctl_ack_eliciting_pkt[XQC_PNS_APP_DATA] = 1;
    xqc_maybe_should_ack(conn, path, xqc_get_pn_ctl(conn, path),
                         XQC_PNS_APP_DATA, 0, now);

    CU_ASSERT_FALSE(path->path_flag
                    & (XQC_PATH_FLAG_SHOULD_ACK_INIT << XQC_PNS_APP_DATA));
    CU_ASSERT_FATAL(timer->timer_is_set);
    return timer->expire_time;
}

void
xqc_test_ack_timer_within_max_ack_delay(void)
{
    xqc_connection_t *conn = test_engine_connect();
    xqc_usec_t now = 1000000;

    CU_ASSERT_FATAL(conn != NULL);

    /* the default 25 ms is advertised, the timer expires 1 ms before */
    CU_ASSERT_EQUAL(conn->local_settings.max_ack_delay, 25);
    CU_ASSERT_EQUAL(xqc_ack_timer_delay(conn), 24000);
    CU_ASSERT_EQUAL(xqc_test_ack_timer_expiry(conn, now), now + 24000);

    /* a larger max_ack_delay */
    conn->local_settings.max_ack_delay = 500;
    CU_ASSERT_EQUAL(xqc_test_ack_timer_expiry(conn, now), now + 499000);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_ack_timer_small_max_ack_delay(void)
{
    xqc_connection_t *conn = test_engine_connect();
    xqc_usec_t now = 1000000;

    CU_ASSERT_FATAL(conn != NULL);

    /* no room for the margin: the timer expires at once, without wrapping */
    conn->local_settings.max_ack_delay = 1;
    CU_ASSERT_EQUAL(xqc_ack_timer_delay(conn), 0);
    CU_ASSERT_EQUAL(xqc_test_ack_timer_expiry(conn, now), now);

    conn->local_settings.max_ack_delay = 0;
    CU_ASSERT_EQUAL(xqc_test_ack_timer_expiry(conn, now), now);

    /* the timer still waits for 2 ms when 3 ms are advertised */
    conn->local_settings.max_ack_delay = 3;
    CU_ASSERT_EQUAL(xqc_test_ack_timer_expiry(conn, now), now + 2000);

    xqc_engine_destroy(conn->engine);
}
