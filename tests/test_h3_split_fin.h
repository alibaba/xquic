/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_TEST_H3_SPLIT_FIN_H_INCLUDED_
#define _XQC_TEST_H3_SPLIT_FIN_H_INCLUDED_

#include <event2/event.h>
#include <stdio.h>
#include <xquic/xqc_http3.h>

#define XQC_TEST_CASE_H3_UPLINK_PURE_FIN         1032
#define XQC_TEST_CASE_H3_DOWNLINK_PURE_FIN       1033
#define XQC_TEST_CASE_H3_UPLINK_EMPTY_DATA_FIN   1034
#define XQC_TEST_CASE_H3_DOWNLINK_EMPTY_DATA_FIN 1035
#define XQC_TEST_H3_SPLIT_FIN_BODY_SIZE          117

typedef struct {
    xqc_h3_request_t    *request;
    xqc_engine_t        *engine;
    struct event_base  *ev_base;
    struct event       *timer;
    const char         *peer;
    int                 case_id;
    int                 sender;
    int                 fin_armed;
    int                 fin_sent;
    int                 app_fin;
    int                 body_before_fin;
    int                 failed;
    size_t              recv_bytes;
} xqc_test_h3_split_fin_t;

static int
xqc_test_h3_split_fin_case(int case_id)
{
    return case_id >= XQC_TEST_CASE_H3_UPLINK_PURE_FIN
           && case_id <= XQC_TEST_CASE_H3_DOWNLINK_EMPTY_DATA_FIN;
}

static int
xqc_test_h3_split_fin_uplink(int case_id)
{
    return case_id == XQC_TEST_CASE_H3_UPLINK_PURE_FIN
           || case_id == XQC_TEST_CASE_H3_UPLINK_EMPTY_DATA_FIN;
}

static void
xqc_test_h3_split_fin_init(xqc_test_h3_split_fin_t *test,
    xqc_h3_request_t *request, xqc_engine_t *engine,
    struct event_base *ev_base, int case_id, const char *peer, int sender)
{
    if (test->request != NULL) {
        return;
    }

    test->request = request;
    test->engine = engine;
    test->ev_base = ev_base;
    test->case_id = case_id;
    test->peer = peer;
    test->sender = sender;
}

static void
xqc_test_h3_split_fin_send_fin(evutil_socket_t fd, short what, void *arg)
{
    (void)fd;
    (void)what;
    xqc_test_h3_split_fin_t *test = arg;
    ssize_t ret;
    int empty_data = test->case_id >= XQC_TEST_CASE_H3_UPLINK_EMPTY_DATA_FIN;

    if (empty_data) {
        /* Send an empty H3 DATA frame and finish the QUIC stream. */
        ret = xqc_h3_request_send_body(test->request, NULL, 0, 1);

    } else {
        ret = xqc_h3_request_finish(test->request);
    }

    test->fin_sent = ret == 0;
    test->failed |= !test->fin_sent;
    printf("[h3-split-fin-test]|case:%d|peer:%s|stage:fin_sent|"
           "kind:%s|ret:%zd|failed:%d|\n",
           test->case_id, test->peer, empty_data ? "empty_data" : "pure",
           ret, test->failed);
    fflush(stdout);
    xqc_engine_main_logic(test->engine);
}

static int
xqc_test_h3_split_fin_after_send(xqc_test_h3_split_fin_t *test, size_t bytes)
{
    if (!test->sender || test->fin_armed) {
        return XQC_OK;
    }

    /* Keep the event loop running for 500 ms between DATA and FIN. */
    struct timeval delay = {0, 500000};
    test->fin_armed = 1;
    test->timer = event_new(test->ev_base, -1, 0,
                            xqc_test_h3_split_fin_send_fin, test);
    if (test->timer == NULL || event_add(test->timer, &delay) != 0) {
        test->failed = 1;
        return XQC_ERROR;
    }

    printf("[h3-split-fin-test]|case:%d|peer:%s|stage:data_sent|"
           "bytes:%zu|fin:0|delay_ms:500|\n",
           test->case_id, test->peer, bytes);
    fflush(stdout);
    return XQC_OK;
}

static void
xqc_test_h3_split_fin_on_read(xqc_test_h3_split_fin_t *test,
    size_t bytes, unsigned char fin, xqc_request_notify_flag_t flag)
{
    test->recv_bytes = bytes;
    test->app_fin |= fin;

    if (!test->sender && !test->body_before_fin && !fin
        && bytes == XQC_TEST_H3_SPLIT_FIN_BODY_SIZE)
    {
        test->body_before_fin = 1;
        printf("[h3-split-fin-test]|case:%d|peer:%s|stage:body_read|"
               "bytes:%zu|app_fin:0|\n",
               test->case_id, test->peer, bytes);
    }

    printf("[h3-split-fin-test]|case:%d|peer:%s|stage:read_notify|"
           "flag:%u|bytes:%zu|app_fin:%d|\n", test->case_id,
           test->peer, (unsigned)flag, bytes, test->app_fin);
    fflush(stdout);
}

static void
xqc_test_h3_split_fin_close(xqc_test_h3_split_fin_t *test)
{
    xqc_h3_request_t *request = test->request;
    if (request == NULL) {
        return;
    }
    xqc_request_stats_t stats = xqc_h3_request_get_stats(request);

    if (test->timer != NULL) {
        event_free(test->timer);
        test->timer = NULL;
    }

    printf("[h3-split-fin-test]|case:%d|peer:%s|stage:close|"
           "bytes:%zu|app_fin:%d|body_before_fin:%d|fin_sent:%d|"
           "fin_seen:%d|rcv_e_set:%d|stream_err:%d|failed:%d|\n",
           test->case_id, test->peer, test->recv_bytes, test->app_fin,
           test->body_before_fin, test->fin_sent, stats.stream_fin_time != 0,
           stats.h3r_end_time != 0, stats.stream_err, test->failed);
    fflush(stdout);
}

#endif
