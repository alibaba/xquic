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

typedef enum {
    XQC_CID_SET_UNUSED,
    XQC_CID_SET_USED,
    XQC_CID_SET_ABANDONED,
    XQC_CID_SET_MAX_STATE,
} xqc_cid_set_state_t;

typedef enum {
    XQC_CID_UNACKED = 0,
    XQC_CID_ACKED   = 1
} xqc_cid_flag_t;

typedef struct xqc_cid_inner_s {
    xqc_list_head_t   list;
    xqc_cid_t         cid;
    xqc_cid_state_t   state;
    xqc_usec_t        retired_ts;
    xqc_cid_flag_t    acked;
} xqc_cid_inner_t;

typedef struct xqc_cid_set_inner_s {
    xqc_list_head_t     next;    /* a list of cid inner structures */
    xqc_list_head_t     cid_list;
    uint64_t            unused_cnt;
    uint64_t            used_cnt;
    uint64_t            retired_cnt;
    uint64_t            path_id;
    union {
    uint64_t            largest_scid_seq_num;    /* for scid set */
    uint64_t            largest_retire_prior_to; /* for dcid set */
    };
    xqc_cid_set_state_t set_state;
    uint32_t            acked_unused;
} xqc_cid_set_inner_t;

typedef struct xqc_cid_set_s {
    xqc_list_head_t   cid_set_list; /* a list of xqc_cid_set_inner_t */
    union {
    unsigned char     original_scid_str[XQC_MAX_CID_LEN * 2 + 1];
    unsigned char     current_dcid_str[XQC_MAX_CID_LEN * 2 + 1];
    };
    union {
    xqc_cid_t         user_scid;    /* one of the USED SCIDs, for create/close notify */
    xqc_cid_t         current_dcid; /* one of the USED DCIDs, for send packets */
    };
    uint32_t          set_cnt[XQC_CID_SET_MAX_STATE];
} xqc_cid_set_t;


xqc_int_t xqc_generate_cid(xqc_engine_t *engine, xqc_cid_t *ori_cid, xqc_cid_t *cid,
    uint64_t cid_seq_num);

void xqc_cid_copy(xqc_cid_t *dst, xqc_cid_t *src);
void xqc_cid_init_zero(xqc_cid_t *cid);
void xqc_cid_set(xqc_cid_t *cid, const unsigned char *data, uint8_t len);

void xqc_init_cid_set(xqc_cid_set_t *cid_set);
void xqc_destroy_cid_set(xqc_cid_set_t *cid_set);

xqc_int_t xqc_cid_set_insert_cid(xqc_cid_set_t *cid_set, xqc_cid_t *cid, 
    xqc_cid_state_t state, uint64_t limit, uint64_t path_id);
xqc_int_t xqc_cid_set_delete_cid(xqc_cid_set_t *cid_set, 
    xqc_cid_t *cid, uint64_t path_id);

xqc_cid_inner_t *xqc_get_inner_cid_by_seq(xqc_cid_set_t *cid_set, 
    uint64_t seq_num, uint64_t path_id);
xqc_cid_inner_t *xqc_cid_in_cid_set(xqc_cid_set_t *cid_set, 
    xqc_cid_t *cid, uint64_t path_id);
xqc_cid_inner_t *xqc_cid_set_search_cid(xqc_cid_set_t *cid_set, 
    xqc_cid_t *cid);

xqc_int_t xqc_cid_switch_to_next_state(xqc_cid_set_t *cid_set, 
    xqc_cid_inner_t *cid, xqc_cid_state_t state, uint64_t path_id);

xqc_int_t xqc_get_unused_cid(xqc_cid_set_t *cid_set, 
    xqc_cid_t *cid, uint64_t path_id);

void xqc_cid_set_inner_init(xqc_cid_set_inner_t *cid_set_inner);
void xqc_cid_set_inner_destroy(xqc_cid_set_inner_t *cid_set_inner);
xqc_cid_set_inner_t* xqc_get_path_cid_set(xqc_cid_set_t *cid_set, uint64_t path_id); 
int64_t xqc_cid_set_get_unused_cnt(xqc_cid_set_t *cid_set, uint64_t path_id);
int64_t xqc_cid_set_get_used_cnt(xqc_cid_set_t *cid_set, uint64_t path_id);\
int64_t xqc_cid_set_get_retired_cnt(xqc_cid_set_t *cid_set, uint64_t path_id);
int64_t xqc_cid_set_get_largest_seq_or_rpt(xqc_cid_set_t *cid_set, uint64_t path_id);
xqc_int_t xqc_cid_set_set_largest_seq_or_rpt(xqc_cid_set_t *cid_set, uint64_t path_id, uint64_t val);

unsigned char *xqc_sr_token_str(xqc_engine_t *engine, const char *sr_token);

xqc_int_t xqc_cid_set_add_path(xqc_cid_set_t *cid_set, uint64_t path_id);

void xqc_cid_set_update_state(xqc_cid_set_t *cid_set, uint64_t path_id, xqc_cid_set_state_t state);

xqc_cid_set_inner_t* xqc_get_next_unused_path_cid_set(xqc_cid_set_t *cid_set);
void xqc_cid_set_on_cid_acked(xqc_cid_set_t *cid_set, uint64_t path_id, uint64_t cid_seq);


#endif /* _XQC_CID_H_INCLUDED_ */

