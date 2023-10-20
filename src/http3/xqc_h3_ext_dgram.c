#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include "src/http3/xqc_h3_ext_dgram.h"
#include "src/http3/xqc_h3_conn.h"

void 
xqc_h3_ext_datagram_read_notify(xqc_connection_t *conn,
    void *user_data, const void *data, size_t data_len, uint64_t recv_time)
{
    xqc_h3_conn_t *h3c = (xqc_h3_conn_t*)conn->proto_data;
    if (h3c->h3_ext_dgram_callbacks.dgram_read_notify
        && (h3c->flags & XQC_H3_CONN_FLAG_UPPER_CONN_EXIST)) 
    {
        h3c->h3_ext_dgram_callbacks.dgram_read_notify(h3c, 
                                                      data, data_len, user_data, recv_time);
        xqc_log(h3c->log, XQC_LOG_DEBUG, "|notify datagram read event to app|");
    }
}

void 
xqc_h3_ext_datagram_write_notify(xqc_connection_t *conn,
    void *user_data)
{
    xqc_h3_conn_t *h3c = (xqc_h3_conn_t*)conn->proto_data;
    if (h3c->h3_ext_dgram_callbacks.dgram_write_notify
        && (h3c->flags & XQC_H3_CONN_FLAG_UPPER_CONN_EXIST)) 
    {
        h3c->h3_ext_dgram_callbacks.dgram_write_notify(h3c, user_data);
        xqc_log(h3c->log, XQC_LOG_DEBUG, 
                "|notify datagram write event to app|");
    }
}

xqc_int_t 
xqc_h3_ext_datagram_lost_notify(xqc_connection_t *conn,
    uint64_t dgram_id, void *user_data)
{
    xqc_int_t ret = 0;
    xqc_h3_conn_t *h3c = (xqc_h3_conn_t*)conn->proto_data;
    if (h3c->h3_ext_dgram_callbacks.dgram_lost_notify
        && (h3c->flags & XQC_H3_CONN_FLAG_UPPER_CONN_EXIST)) 
    {
        ret = h3c->h3_ext_dgram_callbacks.dgram_lost_notify(h3c, dgram_id, user_data);
        xqc_log(h3c->log, XQC_LOG_DEBUG, 
                "|notify lost datagram to app|dgram_id:%ui|",
                dgram_id);
    }
    return ret;
}

void 
xqc_h3_ext_datagram_acked_notify(xqc_connection_t *conn,
    uint64_t dgram_id, void *user_data)
{
    xqc_h3_conn_t *h3c = (xqc_h3_conn_t*)conn->proto_data;
    if (h3c->h3_ext_dgram_callbacks.dgram_acked_notify
        && (h3c->flags & XQC_H3_CONN_FLAG_UPPER_CONN_EXIST)) 
    {
        h3c->h3_ext_dgram_callbacks.dgram_acked_notify(h3c, dgram_id, user_data);
        xqc_log(h3c->log, XQC_LOG_DEBUG, 
                "|notify acked datagram to app|dgram_id:%ui|",
                dgram_id);
    }
}

void
xqc_h3_ext_datagram_mss_updated_notify(xqc_connection_t *conn,
    size_t mss, void *user_data)
{
    xqc_h3_conn_t *h3c = (xqc_h3_conn_t*)conn->proto_data;
    if (h3c->h3_ext_dgram_callbacks.dgram_mss_updated_notify
        && (h3c->flags & XQC_H3_CONN_FLAG_UPPER_CONN_EXIST)) 
    {
        h3c->h3_ext_dgram_callbacks.dgram_mss_updated_notify(h3c, mss, user_data);
        xqc_log(h3c->log, XQC_LOG_DEBUG, 
                "|notify datagram mss to app|mss:%z|", mss);
    }
}

const xqc_datagram_callbacks_t h3_ext_datagram_callbacks = {
    .datagram_read_notify        = xqc_h3_ext_datagram_read_notify,
    .datagram_write_notify       = xqc_h3_ext_datagram_write_notify,
    .datagram_lost_notify        = xqc_h3_ext_datagram_lost_notify,
    .datagram_acked_notify       = xqc_h3_ext_datagram_acked_notify,
    .datagram_mss_updated_notify = xqc_h3_ext_datagram_mss_updated_notify,
};

size_t 
xqc_h3_ext_datagram_get_mss(xqc_h3_conn_t *conn)
{
    return xqc_datagram_get_mss(conn->conn);
}

void 
xqc_h3_ext_datagram_set_user_data(xqc_h3_conn_t *conn, void *user_data)
{
    xqc_datagram_set_user_data(conn->conn, user_data);
}

void *
xqc_h3_ext_datagram_get_user_data(xqc_h3_conn_t *conn)
{
    return xqc_datagram_get_user_data(conn->conn);
}

xqc_int_t 
xqc_h3_ext_datagram_send(xqc_h3_conn_t *conn, void *data, 
	size_t data_len, uint64_t *dgram_id, xqc_data_qos_level_t qos_level)
{
    return xqc_datagram_send(conn->conn, data, data_len, dgram_id, qos_level);
}

xqc_int_t 
xqc_h3_ext_datagram_send_multiple(xqc_h3_conn_t *conn, 
    struct iovec *iov, uint64_t *dgram_id_list, size_t iov_size, 
    size_t *sent_cnt, size_t *sent_bytes, xqc_data_qos_level_t qos_level)
{
    return xqc_datagram_send_multiple(conn->conn, iov, dgram_id_list, iov_size, 
                                      sent_cnt, sent_bytes, qos_level);
}