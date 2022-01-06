/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_CID_H_INCLUDED_
#define _XQC_CID_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include "src/common/xqc_list.h"


#define XQC_DEFAULT_CID_LEN 8

typedef enum {
    XQC_CID_UNUSED, 
    XQC_CID_USED,
    XQC_CID_RETIRED,
    XQC_CID_REMOVED,
} xqc_cid_state_t;


typedef struct xqc_cid_inner_s {
    xqc_list_head_t   list;

    xqc_cid_t         cid;
    xqc_cid_state_t   state;
    xqc_usec_t        retired_ts;
} xqc_cid_inner_t;

typedef struct xqc_cid_set_s {
    xqc_list_head_t   list_head;
    uint64_t          unused_cnt;
    uint64_t          used_cnt;
    uint64_t          retired_cnt;
} xqc_cid_set_t;

typedef struct xqc_scid_set_s {
    xqc_cid_t         user_scid; /* one of the USED SCIDs, for create/close notify */
    xqc_cid_set_t     cid_set;   /* a set of SCID, includes used/unused/retired SCID */
    uint64_t          largest_scid_seq_num;
    unsigned char     original_scid_str[XQC_MAX_CID_LEN * 2 + 1];
} xqc_scid_set_t;

typedef struct xqc_dcid_set_s {
    xqc_cid_t         current_dcid; /* one of the USED DCIDs, for send packets */
    xqc_cid_set_t     cid_set;      /* a set of DCID, includes used/unused/retired DCID */
    uint64_t          largest_retire_prior_to;
    unsigned char     current_dcid_str[XQC_MAX_CID_LEN * 2 + 1];
} xqc_dcid_set_t;


xqc_int_t xqc_generate_cid(xqc_engine_t *engine, xqc_cid_t *ori_cid, xqc_cid_t *cid,
    uint64_t cid_seq_num);


void xqc_cid_copy(xqc_cid_t *dst, xqc_cid_t *src);
void xqc_cid_init_zero(xqc_cid_t *cid);
void xqc_cid_set(xqc_cid_t *cid, const unsigned char *data, uint8_t len);

void xqc_init_scid_set(xqc_scid_set_t *scid_set);
void xqc_init_dcid_set(xqc_dcid_set_t *dcid_set);
void xqc_destroy_cid_set(xqc_cid_set_t *cid_set);

xqc_int_t xqc_cid_set_insert_cid(xqc_cid_set_t *cid_set, xqc_cid_t *cid, xqc_cid_state_t state, uint64_t limit);
xqc_int_t xqc_cid_set_delete_cid(xqc_cid_set_t *cid_set, xqc_cid_t *cid);

xqc_cid_t *xqc_get_cid_by_seq(xqc_cid_set_t *cid_set, uint64_t seq_num);
xqc_cid_inner_t *xqc_get_inner_cid_by_seq(xqc_cid_set_t *cid_set, uint64_t seq_num);
xqc_cid_inner_t *xqc_cid_in_cid_set(const xqc_cid_set_t *cid_set, const xqc_cid_t *cid);

xqc_int_t xqc_cid_switch_to_next_state(xqc_cid_set_t *cid_set, xqc_cid_inner_t *cid, xqc_cid_state_t state);
xqc_int_t xqc_get_unused_cid(xqc_cid_set_t *cid_set, xqc_cid_t *cid);

#endif /* _XQC_CID_H_INCLUDED_ */

