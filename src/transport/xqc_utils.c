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
#include "src/common/xqc_time.h"

int
xqc_conns_pq_push(xqc_pq_t *pq, xqc_connection_t *conn, uint64_t time_us)
{
    xqc_conns_pq_elem_t *elem = (xqc_conns_pq_elem_t *)xqc_pq_push(pq, time_us, &conn);
    if (!elem) {
        xqc_log(conn->log, XQC_LOG_ERROR, "|xqc_pq_push error|count:%uz|capacity:%uz|", pq->count, pq->capacity);
        return -XQC_EMALLOC;
    }
    return XQC_OK;
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

xqc_connection_t *
xqc_conns_pq_pop_top_conn(xqc_pq_t *pq)
{
    /* used to traverse conns_pq */
    xqc_conns_pq_elem_t *el = xqc_conns_pq_top(pq);
    if (XQC_UNLIKELY(el == NULL || el->conn == NULL)) {
        xqc_conns_pq_pop(pq);
        return NULL;
    }

    xqc_connection_t *conn = el->conn;
    xqc_conns_pq_pop(pq);
    return conn;
}

void 
xqc_conns_pq_remove(xqc_pq_t *pq, xqc_connection_t *conn)
{
    xqc_pq_remove(pq, conn->wakeup_pq_index);
}

int
xqc_insert_conns_hash(xqc_str_hash_table_t *conns_hash, xqc_connection_t *conn,
    const uint8_t *data, size_t len)
{
    uint64_t hash = xqc_siphash_get_hash(&conns_hash->siphash_ctx, data, len); 
    xqc_str_hash_element_t c = {
        .str    = {
            .data = (unsigned char *)data,
            .len = len
        },
        .hash   = hash,
        .value  = conn
    };
    
    if (xqc_str_hash_add(conns_hash, c) != XQC_OK) {
        return -XQC_EMALLOC;
    }

    return XQC_OK;
}

int
xqc_remove_conns_hash(xqc_str_hash_table_t *conns_hash, xqc_connection_t *conn,
    const uint8_t *data, size_t len)
{
    uint64_t hash = xqc_siphash_get_hash(&conns_hash->siphash_ctx, data, len); 
    xqc_str_t str = {
        .data   = (unsigned char *)data,
        .len    = len,
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
    uint64_t hash = xqc_siphash_get_hash(&conns_hash->siphash_ctx, (const uint8_t *)addr, addrlen); 
    xqc_str_hash_element_t c = {
        .str    = {
            .data = (unsigned char *)addr,
            .len = addrlen
        },
        .hash   = hash,
        .value  = conn
    };

    if (xqc_str_hash_add(conns_hash, c) != XQC_OK) {
        return -XQC_EMALLOC;
    }
    return 0;
}


void *
xqc_find_conns_hash(xqc_str_hash_table_t *conns_hash, xqc_connection_t *conn,
    const uint8_t *data, size_t len)
{
    uint64_t hash = xqc_siphash_get_hash(&conns_hash->siphash_ctx, data, len); 
    xqc_str_t str = {
        .data   = (unsigned char *)data,
        .len    = len,
    };

    return xqc_str_hash_find(conns_hash, hash, str);
}
