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
            return ret;
        } else if (ret < 0) {
            return ret;
        }
        dgram_blk->data_sent += dgram_size;
    }
    return XQC_OK;
}

xqc_int_t
xqc_wt_session_datagram_send(xqc_wt_session_t *session, void *data,
    uint32_t data_len)
{
    if (session == NULL || session->wt_conn == NULL) {
        return -XQC_EPARAM;
    }

    uint8_t header_buf[8];
    size_t  header_len =
        xqc_wt_encode_h3_datagram_session_id(session->session_id,
            header_buf, sizeof(header_buf));
    if (header_len == 0) {
        return -XQC_EPARAM;
    }

    wt_dgram_blk_t *dgram_blk = NULL;

    size_t   total_len = header_len + data_len;
    uint8_t *buf       = xqc_malloc(total_len);
    if (buf == NULL) {
        return XQC_ERROR;
    }
    memcpy(buf, header_buf, header_len);
    memcpy(buf + header_len, data, data_len);
    dgram_blk = xqc_wt_dgram_blk_create(buf, total_len);
    xqc_free(buf);

    int ret = xqc_wt_datagram_send_blk(session->wt_conn, dgram_blk);
    xqc_wt_dgram_blk_destroy(dgram_blk);
    return ret;
}

xqc_int_t
xqc_webtransport_datagram_send(xqc_webtransport_conn_t *user_conn, void *data,
    uint32_t data_len)
{
    xqc_wt_conn_t *wt_conn = (xqc_wt_conn_t *)user_conn;
    if (wt_conn == NULL || wt_conn->wt_session == NULL) {
        return -XQC_EPARAM;
    }
    return xqc_wt_session_datagram_send(wt_conn->wt_session, data, data_len);
}
