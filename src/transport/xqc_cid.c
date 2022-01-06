/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <xquic/xquic.h>
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_conn.h"
#include "src/common/xqc_random.h"

xqc_int_t
xqc_generate_cid(xqc_engine_t *engine, xqc_cid_t *ori_cid, xqc_cid_t *cid,
    uint64_t cid_seq_num)
{
    unsigned char *buf;
    ssize_t        len, written;

    cid->cid_seq_num = cid_seq_num;
    cid->cid_len = engine->config->cid_len;

    buf = cid->cid_buf;
    len = cid->cid_len;

    if (engine->eng_callback.cid_generate_cb) {
        written = engine->eng_callback.cid_generate_cb(ori_cid, buf, len, engine->user_data);
        if (written < XQC_OK) {
            xqc_log(engine->log, XQC_LOG_ERROR, "|generate cid failed [ret=%z]|", written);
            return -XQC_EGENERATE_CID;
        }
        buf += written;
        len -= written;
    }

    if (len > 0 && (xqc_get_random(engine->rand_generator, buf, len) != XQC_OK)) {
        return -XQC_EGENERATE_CID;
    }

    return XQC_OK;
}


xqc_int_t
xqc_cid_is_equal(const xqc_cid_t *dst, const xqc_cid_t *src)
{
    if (dst == NULL || src == NULL) {
        return XQC_ERROR;
    }

    if (dst->cid_len != src->cid_len) {
        return XQC_ERROR;
    }

    if (xqc_memcmp(dst->cid_buf, src->cid_buf, dst->cid_len)) {
        return XQC_ERROR;
    }

    return XQC_OK;
}

void
xqc_cid_copy(xqc_cid_t *dst, xqc_cid_t *src)
{
    dst->cid_len = src->cid_len;
    xqc_memcpy(dst->cid_buf, src->cid_buf, dst->cid_len);
    dst->cid_seq_num = src->cid_seq_num;
}

void
xqc_cid_init_zero(xqc_cid_t *cid)
{
    cid->cid_len = 0;
    xqc_memzero(cid->cid_buf, XQC_MAX_CID_LEN);
    cid->cid_seq_num = 0;
}

void
xqc_cid_set(xqc_cid_t *cid, const unsigned char *data, uint8_t len)
{
    cid->cid_len = len;
    if (len) {
        xqc_memcpy(cid->cid_buf, data, len);
    }
}

static unsigned char g_scid_buf[XQC_MAX_CID_LEN * 2 + 1];
static unsigned char g_dcid_buf[XQC_MAX_CID_LEN * 2 + 1];

unsigned char *
xqc_dcid_str(const xqc_cid_t *dcid)
{
    xqc_hex_dump(g_dcid_buf, dcid->cid_buf, dcid->cid_len);
    g_dcid_buf[dcid->cid_len * 2] = '\0';
    return g_dcid_buf;
}

unsigned char *
xqc_scid_str(const xqc_cid_t *scid)
{
    xqc_hex_dump(g_scid_buf, scid->cid_buf, scid->cid_len);
    g_scid_buf[scid->cid_len * 2] = '\0';
    return g_scid_buf;
}

unsigned char *
xqc_dcid_str_by_scid(xqc_engine_t *engine, const xqc_cid_t *scid)
{
    xqc_connection_t *conn;
    conn = xqc_engine_conns_hash_find(engine, scid, 's');
    if (!conn) {
        xqc_log(engine->log, XQC_LOG_ERROR, "|can not find connection|");
        return NULL;
    }

    xqc_hex_dump(conn->dcid_set.current_dcid_str, conn->dcid_set.current_dcid.cid_buf,
                 conn->dcid_set.current_dcid.cid_len);
    conn->dcid_set.current_dcid_str[conn->dcid_set.current_dcid.cid_len * 2] = '\0';

    return conn->dcid_set.current_dcid_str;
}

void
xqc_init_cid_set(xqc_cid_set_t *cid_set)
{
    xqc_init_list_head(&cid_set->list_head);
    cid_set->unused_cnt = 0;
    cid_set->used_cnt = 0;
    cid_set->retired_cnt = 0;
}

void
xqc_init_scid_set(xqc_scid_set_t *scid_set)
{
    xqc_init_cid_set(&scid_set->cid_set);
    xqc_cid_init_zero(&scid_set->user_scid);
    scid_set->largest_scid_seq_num = 0;
}

void
xqc_init_dcid_set(xqc_dcid_set_t *dcid_set)
{
    xqc_init_cid_set(&dcid_set->cid_set);
    xqc_cid_init_zero(&dcid_set->current_dcid);
    dcid_set->largest_retire_prior_to = 0;
}

void
xqc_destroy_cid_set(xqc_cid_set_t *cid_set)
{
    xqc_cid_inner_t *cid = NULL;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &cid_set->list_head) {
        cid = xqc_list_entry(pos, xqc_cid_inner_t, list);
        xqc_list_del(pos);
        xqc_free(cid);
    }

    xqc_init_cid_set(cid_set);
}

xqc_int_t
xqc_cid_set_insert_cid(xqc_cid_set_t *cid_set, xqc_cid_t *cid, xqc_cid_state_t state, uint64_t limit)
{
    if (cid_set->unused_cnt + cid_set->used_cnt > limit) {
        return -XQC_EACTIVE_CID_LIMIT;
    }

    xqc_cid_inner_t *inner_cid = xqc_malloc(sizeof(xqc_cid_inner_t));
    if (inner_cid == NULL) {
        return -XQC_EMALLOC;
    }

    xqc_cid_copy(&inner_cid->cid, cid);
    inner_cid->state = state;
    inner_cid->retired_ts = XQC_MAX_UINT64_VALUE;

    xqc_init_list_head(&inner_cid->list);
    xqc_list_add_tail(&inner_cid->list, &cid_set->list_head); 

    if (state == XQC_CID_UNUSED) {
        cid_set->unused_cnt++;

    } else if (state == XQC_CID_USED) {
        cid_set->used_cnt++;

    } else if (state == XQC_CID_RETIRED) {
        cid_set->retired_cnt++;
    }

    return XQC_OK;
}

xqc_int_t
xqc_cid_set_delete_cid(xqc_cid_set_t *cid_set, xqc_cid_t *cid)
{
    xqc_cid_inner_t *inner_cid = NULL;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &cid_set->list_head) {
        inner_cid = xqc_list_entry(pos, xqc_cid_inner_t, list);
        if (xqc_cid_is_equal(cid, &inner_cid->cid) == XQC_OK) {

            if (inner_cid->state == XQC_CID_UNUSED) {
                cid_set->unused_cnt--;

            } else if (inner_cid->state == XQC_CID_USED) {
                cid_set->used_cnt--;

            } else if (inner_cid->state == XQC_CID_RETIRED) {
                cid_set->retired_cnt--;
            }

            xqc_list_del(pos);
            xqc_free(inner_cid);
            return XQC_OK;
        }
    }

    return XQC_ERROR;
}

xqc_cid_inner_t *
xqc_cid_in_cid_set(const xqc_cid_set_t *cid_set, const xqc_cid_t *cid)
{
    xqc_cid_inner_t *inner_cid = NULL;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &cid_set->list_head) {
        inner_cid = xqc_list_entry(pos, xqc_cid_inner_t, list);
        if (xqc_cid_is_equal(cid, &inner_cid->cid) == XQC_OK) {
            return inner_cid;
        }
    }

    return NULL;
}


xqc_int_t
xqc_cid_switch_to_next_state(xqc_cid_set_t *cid_set, xqc_cid_inner_t *cid, xqc_cid_state_t next_state)
{
    if (xqc_cid_in_cid_set(cid_set, &cid->cid) == NULL) {
        return -XQC_ECONN_CID_NOT_FOUND;
    }

    xqc_cid_state_t current_state = cid->state;

    if (current_state == next_state) {
        return XQC_OK;

    } else if (current_state > next_state) {
        return -XQC_ECID_STATE;
    }

    /* current_state < next_state */

    if (current_state == XQC_CID_UNUSED) {
        cid_set->unused_cnt--;

    } else if (current_state == XQC_CID_USED) {
        cid_set->used_cnt--;

    } else if (current_state == XQC_CID_RETIRED) {
        cid_set->retired_cnt--;
    }

    cid->state = next_state;

    if (next_state == XQC_CID_USED) {
        cid_set->used_cnt++;

    } else if (next_state == XQC_CID_RETIRED) {
        cid_set->retired_cnt++;
    }

    return XQC_OK;
}

xqc_int_t
xqc_get_unused_cid(xqc_cid_set_t *cid_set, xqc_cid_t *cid)
{
    if (cid_set->unused_cnt == 0) {
        return -XQC_ECONN_NO_AVAIL_CID;
    }

    xqc_cid_inner_t *inner_cid;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &cid_set->list_head) {
        inner_cid = xqc_list_entry(pos, xqc_cid_inner_t, list);

        if (inner_cid->state == XQC_CID_UNUSED) {
            xqc_cid_copy(cid, &inner_cid->cid);
            return xqc_cid_switch_to_next_state(cid_set, inner_cid, XQC_CID_USED);
        }
    }

    return -XQC_ECONN_NO_AVAIL_CID;
}

xqc_cid_t *
xqc_get_cid_by_seq(xqc_cid_set_t *cid_set, uint64_t seq_num)
{
    xqc_cid_inner_t *inner_cid = NULL;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &cid_set->list_head) {
        inner_cid = xqc_list_entry(pos, xqc_cid_inner_t, list);

        if (inner_cid->cid.cid_seq_num == seq_num) {
            return &inner_cid->cid;
        }
    }

    return NULL;
}

xqc_cid_inner_t *
xqc_get_inner_cid_by_seq(xqc_cid_set_t *cid_set, uint64_t seq_num)
{
    xqc_cid_inner_t *inner_cid = NULL;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &cid_set->list_head) {
        inner_cid = xqc_list_entry(pos, xqc_cid_inner_t, list);

        if (inner_cid->cid.cid_seq_num == seq_num) {
            return inner_cid;
        }
    }

    return NULL;
}
