/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_hq.h"
#include "xqc_hq_request.h"
#include "xqc_hq_ctx.h"
#include "xqc_hq_conn.h"
#include "xqc_hq_defs.h"

#include "src/common/xqc_common_inc.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_conn.h"


#define XQC_HQ_REQUEST_BASE_LEN             7
#define XQC_HQ_REQUEST_MAX_LEN              512
#define XQC_HQ_REQUEST_RESOURCE_MAX_LEN     256
#define XQC_HQ_RESPONSE_MAX_LEN             4096


typedef struct xqc_hq_request_s {
    /**
     * transport-level callback functions, taken over by hq request
     */
    xqc_hq_request_callbacks_t *hqr_cbs;

    /**
     * app-level user_data, which will be used when hq-level callback functions are triggered
     */
    void                       *user_data;

    /* 
     * quic-level stream, we will always make xqc_hq_request_t instance the user_data of
     * xqc_stream_t. if the user_data of stream callback functions is NULL, it means 
     * xqc_hq_request_t has not been created yet.
     */
    xqc_stream_t               *stream;

    /**
     * send buffer
     */
    uint8_t                    *send_buf;
    size_t                      send_buf_len;
    size_t                      sent_cnt;

    /**
     * request recv buffer
     */
    uint8_t                    *req_recv_buf;
    size_t                      recv_buf_len;
    size_t                      recv_cnt;

    /**
     * buffer for read request
     */
    uint8_t                    *resource_buf;
    size_t                      resource_buf_sz;
    size_t                      resource_read_offset;
    uint8_t                     fin;
} xqc_hq_request_s;



/* active create request, used by client */
xqc_hq_request_t *
xqc_hq_request_create(xqc_engine_t *engine, xqc_hq_conn_t *hqc, const xqc_cid_t *cid,
    void *user_data)
{
    xqc_hq_request_t *hqr = NULL;
    xqc_stream_t *stream = NULL;

    /* malloc hqr */
    hqr = xqc_calloc(1, sizeof(xqc_hq_request_t));
    if (NULL == hqr) {
        PRINT_LOG("malloc error|");
        return NULL;
    }

    /* init app-level callbacks */
    if (xqc_hq_ctx_get_request_callbacks(&hqr->hqr_cbs) != XQC_OK) {
        PRINT_LOG("get app-level request callbacks error\n");
        goto fail;
    }

    /* create stream, make hqr the user_data of xqc_stream_t */
    stream = xqc_stream_create(engine, cid, hqr);
    if (NULL == stream) {
        PRINT_LOG("create transport-level stream error");
        goto fail;
    }

    hqr->stream = stream;
    hqr->user_data = user_data; /* make app-level user_data the user_data xqc_hq_request_t */

    return hqr;

fail:
    if (hqr) {
        xqc_hq_request_destroy(hqr);
    }

    return NULL;
}


/* passive create request, used by server */
xqc_hq_request_t *
xqc_hq_request_create_passive(xqc_stream_t *stream)
{
    xqc_hq_request_t *hqr = xqc_calloc(1, sizeof(xqc_hq_request_t));
    if (NULL == hqr) {
        return NULL;
    }

    /* init app-level callbacks */
    if (xqc_hq_ctx_get_request_callbacks(&hqr->hqr_cbs) != XQC_OK) {
        PRINT_LOG("get app-level request callbacks error");
        xqc_hq_request_destroy(hqr);
        return NULL;
    }

    /* make hqr the user_data of xqc_stream_t */
    xqc_stream_set_user_data(stream, hqr);

    hqr->stream = stream;
    hqr->user_data = NULL;  /* app-level user_data is temporary NULL */

    return hqr;
}


void
xqc_hq_request_destroy(xqc_hq_request_t *hqr)
{
    if (hqr) {
        if (hqr->send_buf) {
            xqc_free(hqr->send_buf);
            hqr->send_buf = NULL;
        }

        if (hqr->req_recv_buf) {
            xqc_free(hqr->req_recv_buf);
            hqr->req_recv_buf = NULL;
        }

        if (hqr->resource_buf) {
            xqc_free(hqr->resource_buf);
            hqr->resource_buf = NULL;
        }

        xqc_free(hqr);
    }
}


xqc_int_t
xqc_hq_request_close(xqc_hq_request_t *hqr)
{
    xqc_int_t ret = xqc_stream_close(hqr->stream);
    if (ret != XQC_OK) {
        PRINT_LOG("|quic stream close fail|ret:%d|stream_id:%"PRIu64"|", ret, hqr->stream->stream_id);
        return ret;
    }

    return XQC_OK;
}


ssize_t
xqc_hq_request_send_data(xqc_hq_request_t *hqr, const uint8_t *data, size_t len, uint8_t fin)
{
    ssize_t ret = 0;
    while (hqr->sent_cnt < hqr->send_buf_len) {
        ret = xqc_stream_send(hqr->stream, hqr->send_buf + hqr->sent_cnt, 
                              hqr->send_buf_len - hqr->sent_cnt, 1);
        if (ret < 0) {
            if (ret == -XQC_EAGAIN) {
                return 0;

            } else {
                PRINT_LOG("|send req error|ret:%"PRId64"", ret);
                return ret;
            }
        }

        hqr->sent_cnt += ret;
    }

    return ret;
}


ssize_t
xqc_hq_request_send_req(xqc_hq_request_t *hqr, const char *resource)
{
    ssize_t ret = 0;

    if (hqr->send_buf) {
        PRINT_LOG("|request exists on stream|stream_id:%"PRIu64"|", hqr->stream->stream_id);
        return -XQC_EFATAL;
    }

    size_t max_req_buf_len = strlen(resource) + XQC_HQ_REQUEST_BASE_LEN;
    hqr->send_buf = xqc_malloc(max_req_buf_len);
    if (NULL == hqr->send_buf) {
        PRINT_LOG("|request exists on stream|stream_id:%"PRIu64"|", hqr->stream->stream_id);
        return -XQC_EMALLOC;
    }

    /* format HQ request */
    hqr->send_buf_len = snprintf(hqr->send_buf, max_req_buf_len, "GET %s\r\n", resource);
    ret = xqc_hq_request_send_data(hqr, hqr->send_buf, hqr->send_buf_len, 1);
    if (ret < 0) {
        PRINT_LOG("|send request error|ret: %"PRIu64"|", ret);
        return ret;
    }

    return strlen(resource);
}


ssize_t
xqc_hq_request_send_rsp(xqc_hq_request_t *hqr, const uint8_t *res_buf, size_t res_buf_len,
    uint8_t fin)
{
    ssize_t ret = xqc_stream_send(hqr->stream, (unsigned char *)res_buf, res_buf_len, fin);
    if (ret == -XQC_EAGAIN) {
        ret = 0;
    }

    return ret;
}


ssize_t
xqc_hq_parse_req(xqc_hq_request_t *hqr, char *res, size_t sz)
{
    char method[16] = {0};
    int ret = sscanf(hqr->req_recv_buf, "%s %s", method, res);
    if (ret <= 0) {
        PRINT_LOG("|parse hq request failed: %s", hqr->req_recv_buf);
        return -XQC_EPROTO;
    }

    return strlen(res);
}

ssize_t
xqc_hq_request_recv_req(xqc_hq_request_t *hqr, char *res_buf, size_t buf_sz, uint8_t *fin)
{
    if (hqr->req_recv_buf == NULL) {
        hqr->req_recv_buf = xqc_malloc(XQC_HQ_REQUEST_MAX_LEN);
        if (NULL == hqr->req_recv_buf) {
            return -XQC_EMALLOC;
        }

        hqr->recv_buf_len = XQC_HQ_REQUEST_MAX_LEN;
    }

    *fin = 0;
    ssize_t read = 0;
    do {
        read = xqc_stream_recv(hqr->stream, hqr->req_recv_buf + hqr->recv_cnt, 
                               hqr->recv_buf_len - hqr->recv_cnt, &hqr->fin);
        if (read == -XQC_EAGAIN) {
            break;

        } else if (read < 0) {
            PRINT_LOG("|xqc_stream_recv error %"PRId64"|", read);
            return 0;
        }

        hqr->recv_cnt += read;
        if (hqr->recv_cnt == hqr->recv_buf_len && hqr->fin) {
            PRINT_LOG("|impossible resource len!|");
            return -XQC_EFATAL;
        }

    } while (read > 0 && !hqr->fin);

    /* return until all request bytes are received */
    if (!hqr->fin) {
        return XQC_OK;
    }

    if (NULL == hqr->resource_buf) {
        hqr->resource_buf = xqc_malloc(XQC_HQ_REQUEST_RESOURCE_MAX_LEN);
        if (NULL == hqr->resource_buf) {
            return -XQC_EMALLOC;
        }

        hqr->resource_buf_sz = XQC_HQ_REQUEST_RESOURCE_MAX_LEN;
    }

    read = xqc_hq_parse_req(hqr, hqr->resource_buf, XQC_HQ_REQUEST_RESOURCE_MAX_LEN);
    if (read <= 0) {
        return -XQC_EPROTO;
    }

    if (buf_sz < hqr->resource_read_offset) {
        return -XQC_ENOBUF;
    }

    if (hqr->resource_read_offset < strlen(hqr->resource_buf)) {
        read = (ssize_t)strncpy(res_buf, hqr->resource_buf, buf_sz);
        hqr->resource_read_offset += read;
        *fin = hqr->fin;
    }

    return read;
}

ssize_t
xqc_hq_request_recv_rsp(xqc_hq_request_t *hqr, char *res_buf, size_t buf_sz, uint8_t *fin)
{
    return xqc_stream_recv(hqr->stream, res_buf, buf_sz, fin);
}

void
xqc_hq_request_set_user_data(xqc_hq_request_t *hqr, void *user_data)
{
    hqr->user_data = user_data;
}


int
xqc_hq_stream_create_notify(xqc_stream_t *stream, void *strm_user_data)
{
    xqc_hq_request_t *hqr = (xqc_hq_request_t *)strm_user_data;
    /* the stream of server is passive created, and it's strm_user_data is NULL */
    if (hqr == NULL) {
        hqr = xqc_hq_request_create_passive(stream);
        if (NULL == hqr) {
            return -XQC_EMALLOC;
        }
    }

    /* notify to app-level */
    if (hqr->hqr_cbs->req_create_notify) {
        return hqr->hqr_cbs->req_create_notify(hqr, hqr->user_data);
    }

    return XQC_OK;
}


int
xqc_hq_stream_write_notify(xqc_stream_t *stream, void *user_data)
{
    xqc_hq_request_t *hqr = (xqc_hq_request_t *)user_data;

    ssize_t ret = xqc_hq_request_send_data(hqr, hqr->send_buf + hqr->sent_cnt,
        hqr->send_buf_len - hqr->sent_cnt, 1);
    if (ret < 0) {
        return (int)ret;
    }

    if (hqr->hqr_cbs->req_write_notify) {
        return hqr->hqr_cbs->req_write_notify(hqr, hqr->user_data);
    }

    return XQC_OK;
}


int
xqc_hq_stream_read_notify(xqc_stream_t *stream, void *user_data)
{
    xqc_hq_request_t *hqr = (xqc_hq_request_t *)user_data;
    if (hqr->hqr_cbs->req_read_notify) {
        return hqr->hqr_cbs->req_read_notify(hqr, hqr->user_data);
    }

    return XQC_OK;
}


int
xqc_hq_stream_close_notify(xqc_stream_t *stream, void *user_data)
{
    int ret = 0;
    xqc_hq_request_t *hqr = (xqc_hq_request_t *)user_data;
    if (hqr->hqr_cbs && hqr->hqr_cbs->req_close_notify) {
        ret = hqr->hqr_cbs->req_close_notify(hqr, hqr->user_data);
    }

    xqc_hq_request_destroy(hqr);
    return XQC_OK;
}

/**
 * transport callback
 */
const xqc_stream_callbacks_t hq_stream_callbacks = {
    .stream_create_notify   = xqc_hq_stream_create_notify,
    .stream_write_notify    = xqc_hq_stream_write_notify,
    .stream_read_notify     = xqc_hq_stream_read_notify,
    .stream_close_notify    = xqc_hq_stream_close_notify,
};
