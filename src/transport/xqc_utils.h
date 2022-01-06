/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_UTILS_H_INCLUDED_
#define _XQC_UTILS_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include "src/common/xqc_priority_q.h"

typedef struct xqc_conns_pq_elem_s {
    xqc_pq_key_t        time_ms;
    xqc_connection_t   *conn;
} xqc_conns_pq_elem_t;

int xqc_conns_pq_push(xqc_pq_t *pq, xqc_connection_t *conn, uint64_t time_ms);

void xqc_conns_pq_pop(xqc_pq_t *pq);

xqc_conns_pq_elem_t *xqc_conns_pq_top(xqc_pq_t *pq);

int xqc_insert_conns_hash(xqc_str_hash_table_t *conns_hash, xqc_connection_t *conn, xqc_cid_t *cid);

int xqc_remove_conns_hash(xqc_str_hash_table_t *conns_hash, xqc_connection_t *conn, xqc_cid_t *cid);

void *xqc_find_conns_hash(xqc_str_hash_table_t *conns_hash, xqc_connection_t *conn, xqc_cid_t *cid);

#endif /* _XQC_UTILS_H_INCLUDED_ */
