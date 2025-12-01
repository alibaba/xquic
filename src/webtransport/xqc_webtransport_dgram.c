/**
 * xqc_webtransport_dgram.c
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_webtransport_dgram.h"
#include "src/common/utils/var_buf/xqc_var_buf.h"
#include "src/common/xqc_malloc.h"
#include "src/http3/xqc_h3_defs.h"
#include "src/transport/xqc_conn.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_defs.h"
#include "src/webtransport/xqc_webtransport_session.h"
#include "src/webtransport/xqc_webtransport_wire.h"

xqc_int_t
xqc_wt_datagram_send_blk(xqc_wt_conn_t *user_conn, wt_dgram_blk_t *dgram_blk)
{
    int      ret = 0;
    uint64_t dgram_id = 0;
    while (dgram_blk->data_sent < dgram_blk->to_send_size) {

        size_t dgram_size = dgram_blk->to_send_size - dgram_blk->data_sent;
        if (user_conn->dgram_mss && dgram_size > user_conn->dgram_mss) {
            dgram_size = user_conn->dgram_mss;
        }
        ret = xqc_datagram_send(xqc_h3_conn_get_xqc_conn(user_conn->h3_conn),
            dgram_blk->data + dgram_blk->data_sent, dgram_size, &dgram_id,
            XQC_DATA_QOS_HIGHEST);
        if (ret == -XQC_EAGAIN) {
            printf("[dgram]|retry_datagram_send_later|\n");
            return ret;
        } else if (ret < 0) {
            printf("[dgram]|send_datagram_error|err_code:%d|\n", ret);
            return ret;
        }
        dgram_blk->data_sent += dgram_size;
    }
    return XQC_OK;
}

xqc_int_t
xqc_webtransport_datagram_send(xqc_webtransport_conn_t *user_conn, void *data,
    uint32_t data_len)
{
    xqc_wt_conn_t *wt_conn = (xqc_wt_conn_t *)user_conn;

    uint64_t session_id = 0;
    if (wt_conn && wt_conn->wt_session) {
        session_id = wt_conn->wt_session->sessionID;
    }

    uint8_t header_buf[8];
    size_t  header_len =
        xqc_wt_encode_session_id(session_id, header_buf, sizeof(header_buf));

    wt_dgram_blk_t *dgram_blk = NULL;

    if (header_len > 0) {
        size_t   total_len = header_len + data_len;
        uint8_t *buf       = xqc_malloc(total_len);
        if (buf == NULL) {
            return XQC_ERROR;
        }
        memcpy(buf, header_buf, header_len);
        memcpy(buf + header_len, data, data_len);
        dgram_blk = xqc_wt_dgram_blk_create(buf, total_len);
        xqc_free(buf);
    } else {
        dgram_blk = xqc_wt_dgram_blk_create(data, data_len);
    }

    int ret = xqc_wt_datagram_send_blk(wt_conn, dgram_blk);
    xqc_wt_dgram_blk_destroy(dgram_blk);
    return ret;
}
