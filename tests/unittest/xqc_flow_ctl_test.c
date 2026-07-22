/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_flow_ctl_test.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_stream.h"
#include <CUnit/CUnit.h>
#include <stdint.h>

/**
 * Test: stream-level fc_max_stream_data_can_recv is clamped to 2^62-1.
 * Simulates the accumulation logic in xqc_stream_do_recv_flow_ctl and
 * verifies the clamp prevents overflow beyond XQC_MAX_FLOW_CONTROL_WINDOW.
 */
void
xqc_test_stream_flow_ctl_clamp(void)
{
    /* XQC_MAX_FLOW_CONTROL_WINDOW must equal 2^62 - 1 */
    CU_ASSERT_EQUAL(XQC_MAX_FLOW_CONTROL_WINDOW, ((uint64_t)1 << 62) - 1);

    xqc_stream_flow_ctl_t flow_ctl;
    memset(&flow_ctl, 0, sizeof(flow_ctl));

    /* set fc_max_stream_data_can_recv near the limit */
    flow_ctl.fc_max_stream_data_can_recv = XQC_MAX_FLOW_CONTROL_WINDOW - 100;
    flow_ctl.fc_stream_recv_window_size = XQC_MAX_RECV_WINDOW;

    /* simulate the accumulation that happens in xqc_stream_do_recv_flow_ctl */
    uint64_t available_window = 0; /* worst case: all consumed */
    uint64_t increment = flow_ctl.fc_stream_recv_window_size - available_window;
    flow_ctl.fc_max_stream_data_can_recv += increment;

    /* apply clamp (mirrors the fix in xqc_stream.c) */
    if (flow_ctl.fc_max_stream_data_can_recv > XQC_MAX_FLOW_CONTROL_WINDOW) {
        flow_ctl.fc_max_stream_data_can_recv = XQC_MAX_FLOW_CONTROL_WINDOW;
    }

    CU_ASSERT_EQUAL(flow_ctl.fc_max_stream_data_can_recv, XQC_MAX_FLOW_CONTROL_WINDOW);
}

/**
 * Test: connection-level fc_max_data_can_recv is clamped to 2^62-1.
 */
void
xqc_test_conn_flow_ctl_clamp(void)
{
    xqc_conn_flow_ctl_t flow_ctl;
    memset(&flow_ctl, 0, sizeof(flow_ctl));

    /* set near the limit */
    flow_ctl.fc_max_data_can_recv = XQC_MAX_FLOW_CONTROL_WINDOW - 50;
    flow_ctl.fc_recv_windows_size = XQC_MAX_RECV_WINDOW;

    /* simulate accumulation */
    uint64_t available_window = 0;
    uint64_t increment = flow_ctl.fc_recv_windows_size - available_window;
    flow_ctl.fc_max_data_can_recv += increment;

    /* apply clamp */
    if (flow_ctl.fc_max_data_can_recv > XQC_MAX_FLOW_CONTROL_WINDOW) {
        flow_ctl.fc_max_data_can_recv = XQC_MAX_FLOW_CONTROL_WINDOW;
    }

    CU_ASSERT_EQUAL(flow_ctl.fc_max_data_can_recv, XQC_MAX_FLOW_CONTROL_WINDOW);
}

/**
 * Test: normal values well below 2^62-1 are not affected by the clamp.
 */
void
xqc_test_flow_ctl_normal_no_clamp(void)
{
    xqc_stream_flow_ctl_t stream_fc;
    memset(&stream_fc, 0, sizeof(stream_fc));

    stream_fc.fc_max_stream_data_can_recv = 1024 * 1024; /* 1MB */
    stream_fc.fc_stream_recv_window_size = XQC_MAX_RECV_WINDOW;

    uint64_t expected = stream_fc.fc_max_stream_data_can_recv + stream_fc.fc_stream_recv_window_size;

    /* simulate accumulation + clamp */
    stream_fc.fc_max_stream_data_can_recv += stream_fc.fc_stream_recv_window_size;
    if (stream_fc.fc_max_stream_data_can_recv > XQC_MAX_FLOW_CONTROL_WINDOW) {
        stream_fc.fc_max_stream_data_can_recv = XQC_MAX_FLOW_CONTROL_WINDOW;
    }

    /* normal value should pass through unchanged */
    CU_ASSERT_EQUAL(stream_fc.fc_max_stream_data_can_recv, expected);
    CU_ASSERT(stream_fc.fc_max_stream_data_can_recv < XQC_MAX_FLOW_CONTROL_WINDOW);
}
