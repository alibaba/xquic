/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/common/xqc_common.h"
#include "src/common/xqc_malloc.h"
#include "src/common/xqc_str_hash.h"
#include "src/common/xqc_hash.h"
#include "src/common/xqc_log.h"
#include "src/transport/xqc_utils.h"
#include "src/transport/xqc_conn.h"


int
xqc_conns_pq_push(xqc_pq_t *pq, xqc_connection_t *conn, uint64_t time_ms)
{
    xqc_conns_pq_elem_t *elem = (xqc_conns_pq_elem_t *)xqc_pq_push(pq, time_ms);
    if (!elem) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_pq_push error|count:%uz|capacity:%uz|", pq->count, pq->capacity);
        return -XQC_EMALLOC;
    }
    elem->conn = conn;
    return 0;
}

void
xqc_conns_pq_pop(xqc_pq_t *pq)
{
    xqc_pq_pop(pq);
}

xqc_conns_pq_elem_t *
xqc_conns_pq_top(xqc_pq_t *pq)
{
    return  (xqc_conns_pq_elem_t *)xqc_pq_top(pq);
}

int
xqc_insert_conns_hash(xqc_str_hash_table_t *conns_hash, xqc_connection_t *conn, xqc_cid_t *cid)
{
    uint64_t hash = xqc_hash_string(cid->cid_buf, cid->cid_len);

    xqc_str_hash_element_t c = {
        .str    = {
            .data = cid->cid_buf,
            .len = cid->cid_len
        },
        .hash   = hash,
        .value  = conn
    };

    if (xqc_str_hash_add(conns_hash, c)) {
        return -XQC_EMALLOC;
    }
    return 0;
}

int
xqc_remove_conns_hash(xqc_str_hash_table_t *conns_hash, xqc_connection_t *conn, xqc_cid_t *cid)
{
    uint64_t hash = xqc_hash_string(cid->cid_buf, cid->cid_len);
    xqc_str_t str = {
        .data   = cid->cid_buf,
        .len    = cid->cid_len,
    };

    if (xqc_str_hash_delete(conns_hash, hash, str)) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|xqc_str_hash_delete error|");
        return -XQC_ECONN_NFOUND;
    }
    return 0;
}

int
xqc_insert_conns_addr_hash(xqc_str_hash_table_t *conns_hash, xqc_connection_t *conn,
    const struct sockaddr *addr, socklen_t addrlen)
{
    uint64_t hash = xqc_hash_string((unsigned char*)addr, addrlen);
    xqc_str_hash_element_t c = {
        .str    = {
            .data = (unsigned char*)addr,
            .len = addrlen
        },
        .hash   = hash,
        .value  = conn
    };

    if (xqc_str_hash_add(conns_hash, c)) {
        return -XQC_EMALLOC;
    }
    return 0;
}


void *
xqc_find_conns_hash(xqc_str_hash_table_t *conns_hash, xqc_connection_t *conn, xqc_cid_t *cid)
{
    uint64_t hash = xqc_hash_string(cid->cid_buf, cid->cid_len);
    xqc_str_t str = {
        .data   = cid->cid_buf,
        .len    = cid->cid_len,
    };

    return xqc_str_hash_find(conns_hash, hash, str);
}