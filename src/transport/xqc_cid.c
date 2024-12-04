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

    cid->path_id = XQC_INITIAL_PATH_ID; /* default initial path_id = 0 */

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
    xqc_memcpy(dst->sr_token, src->sr_token, XQC_STATELESS_RESET_TOKENLEN);
    dst->path_id = src->path_id;
}

void
xqc_cid_init_zero(xqc_cid_t *cid)
{
    cid->cid_len = 0;
    cid->cid_seq_num = 0;
    cid->path_id = 0;
}

void
xqc_cid_set(xqc_cid_t *cid, const unsigned char *data, uint8_t len)
{
    cid->cid_len = len;
    if (len) {
        xqc_memcpy(cid->cid_buf, data, len);
    }
}

static unsigned char g_sr_token_buf[XQC_STATELESS_RESET_TOKENLEN * 2 + 1];

unsigned char *
xqc_dcid_str(xqc_engine_t *engine, const xqc_cid_t *dcid)
{
    xqc_hex_dump(engine->dcid_buf, dcid->cid_buf, dcid->cid_len);
    engine->dcid_buf[dcid->cid_len * 2] = '\0';
    return engine->dcid_buf;
}

unsigned char *
xqc_scid_str(xqc_engine_t *engine, const xqc_cid_t *scid)
{
    xqc_hex_dump(engine->scid_buf, scid->cid_buf, scid->cid_len);
    engine->scid_buf[scid->cid_len * 2] = '\0';
    return engine->scid_buf;
}

unsigned char *
xqc_sr_token_str(xqc_engine_t *engine, const char *sr_token)
{
    xqc_hex_dump(engine->sr_token_buf, sr_token, XQC_STATELESS_RESET_TOKENLEN);
    engine->sr_token_buf[XQC_STATELESS_RESET_TOKENLEN * 2] = '\0';
    return engine->sr_token_buf;
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
    xqc_memzero(cid_set, sizeof(xqc_cid_set_t));
    xqc_init_list_head(&cid_set->cid_set_list);
}

void 
xqc_cid_set_inner_init(xqc_cid_set_inner_t *cid_set_inner)
{
    xqc_memzero(cid_set_inner, sizeof(xqc_cid_set_inner_t));
    xqc_init_list_head(&cid_set_inner->cid_list);
    xqc_init_list_head(&cid_set_inner->next);
}

void 
xqc_cid_set_inner_destroy(xqc_cid_set_inner_t *cid_set_inner)
{
    xqc_cid_inner_t *cid = NULL;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &cid_set_inner->cid_list) {
        cid = xqc_list_entry(pos, xqc_cid_inner_t, list);
        xqc_list_del(pos);
        xqc_free(cid);
    }

    xqc_cid_set_inner_init(cid_set_inner);
}

void
xqc_destroy_cid_set(xqc_cid_set_t *cid_set)
{
    xqc_cid_set_inner_t *cid_set_inner = NULL;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &cid_set->cid_set_list) {
        cid_set_inner = xqc_list_entry(pos, xqc_cid_set_inner_t, next);
        xqc_list_del(pos);
        xqc_cid_set_inner_destroy(cid_set_inner);
        xqc_free(cid_set_inner);
    }

    xqc_init_cid_set(cid_set);
}

xqc_cid_set_inner_t* 
xqc_get_path_cid_set(xqc_cid_set_t *cid_set, uint64_t path_id)
{
    xqc_cid_set_inner_t *cid_set_inner = NULL;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &cid_set->cid_set_list) {
        cid_set_inner = xqc_list_entry(pos, xqc_cid_set_inner_t, next);
        if (cid_set_inner->path_id == path_id) {
            return cid_set_inner;
        }
    }

    return NULL;
}

xqc_cid_set_inner_t* 
xqc_get_next_unused_path_cid_set(xqc_cid_set_t *cid_set)
{
    xqc_cid_set_inner_t *cid_set_inner = NULL;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &cid_set->cid_set_list) {
        cid_set_inner = xqc_list_entry(pos, xqc_cid_set_inner_t, next);
        if (cid_set_inner->set_state == XQC_CID_SET_UNUSED) {
            return cid_set_inner;
        }
    }

    return NULL;
} 

int64_t 
xqc_cid_set_get_unused_cnt(xqc_cid_set_t *cid_set, uint64_t path_id)
{
    xqc_cid_set_inner_t *inner_set;
    inner_set = xqc_get_path_cid_set(cid_set, path_id);
    if (inner_set) {
        return inner_set->unused_cnt;
    }
    return XQC_ERROR;
}

int64_t 
xqc_cid_set_get_used_cnt(xqc_cid_set_t *cid_set, uint64_t path_id)
{
    xqc_cid_set_inner_t *inner_set;
    inner_set = xqc_get_path_cid_set(cid_set, path_id);
    if (inner_set) {
        return inner_set->used_cnt;
    }
    return XQC_ERROR;
}

int64_t 
xqc_cid_set_get_retired_cnt(xqc_cid_set_t *cid_set, uint64_t path_id)
{
    xqc_cid_set_inner_t *inner_set;
    inner_set = xqc_get_path_cid_set(cid_set, path_id);
    if (inner_set) {
        return inner_set->retired_cnt;
    }
    return XQC_ERROR;
}

int64_t 
xqc_cid_set_get_largest_seq_or_rpt(xqc_cid_set_t *cid_set, uint64_t path_id)
{
    xqc_cid_set_inner_t *inner_set;
    inner_set = xqc_get_path_cid_set(cid_set, path_id);
    if (inner_set) {
        return inner_set->largest_scid_seq_num;
    }
    return XQC_ERROR;
}

xqc_int_t 
xqc_cid_set_set_largest_seq_or_rpt(xqc_cid_set_t *cid_set, uint64_t path_id, uint64_t val)
{
    xqc_cid_set_inner_t *inner_set;
    inner_set = xqc_get_path_cid_set(cid_set, path_id);
    if (inner_set) {
        inner_set->largest_scid_seq_num = val;
        return XQC_OK;
    }
    return XQC_ERROR;
}

xqc_int_t
xqc_cid_set_insert_cid(xqc_cid_set_t *cid_set,
    xqc_cid_t *cid, xqc_cid_state_t state, uint64_t limit, uint64_t path_id)
{
    xqc_cid_set_inner_t *inner_set;
    inner_set = xqc_get_path_cid_set(cid_set, path_id);
    if (!inner_set) {
        return -XQC_ECONN_CID_NOT_FOUND;
    }

    if ((inner_set->unused_cnt + inner_set->used_cnt) > limit) {
        return -XQC_EACTIVE_CID_LIMIT;
    }

    xqc_cid_inner_t *inner_cid = xqc_calloc(1, sizeof(xqc_cid_inner_t));
    if (inner_cid == NULL) {
        return -XQC_EMALLOC;
    }
    cid->path_id = path_id;

    xqc_cid_copy(&inner_cid->cid, cid);
    inner_cid->state = state;
    inner_cid->retired_ts = XQC_MAX_UINT64_VALUE;

    xqc_init_list_head(&inner_cid->list);
    xqc_list_add_tail(&inner_cid->list, &inner_set->cid_list); 

    if (state == XQC_CID_UNUSED) {
        inner_set->unused_cnt++;

    } else if (state == XQC_CID_USED) {
        inner_set->used_cnt++;

    } else if (state == XQC_CID_RETIRED) {
        inner_set->retired_cnt++;
    }

    return XQC_OK;
}

xqc_int_t
xqc_cid_set_delete_cid(xqc_cid_set_t *cid_set, xqc_cid_t *cid, uint64_t path_id)
{
    xqc_cid_inner_t *inner_cid = NULL;
    xqc_list_head_t *pos, *next;

    xqc_cid_set_inner_t *inner_set;
    inner_set = xqc_get_path_cid_set(cid_set, path_id);

    if (!inner_set) {
        return XQC_ERROR;
    }

    xqc_list_for_each_safe(pos, next, &inner_set->cid_list) {
        inner_cid = xqc_list_entry(pos, xqc_cid_inner_t, list);
        if (xqc_cid_is_equal(cid, &inner_cid->cid) == XQC_OK) {

            if (inner_cid->state == XQC_CID_UNUSED) {
                inner_set->unused_cnt--;
                if (inner_cid->acked == XQC_CID_ACKED) {
                    inner_set->acked_unused--;
                }

            } else if (inner_cid->state == XQC_CID_USED) {
                inner_set->used_cnt--;

            } else if (inner_cid->state == XQC_CID_RETIRED) {
                inner_set->retired_cnt--;
            }

            xqc_list_del(pos);
            xqc_free(inner_cid);
            return XQC_OK;
        }
    }

    return XQC_ERROR;
}
xqc_cid_inner_t *
xqc_cid_set_search_cid(xqc_cid_set_t *cid_set, 
    xqc_cid_t *cid)
{
    xqc_cid_inner_t *inner_cid;
    xqc_list_head_t *pos, *next;
    xqc_cid_set_inner_t *inner_set;
    xqc_list_head_t *pos_set, *next_set;

    xqc_list_for_each_safe(pos_set, next_set, &cid_set->cid_set_list) {
        inner_set = xqc_list_entry(pos_set, xqc_cid_set_inner_t, next);

        xqc_list_for_each_safe(pos, next, &inner_set->cid_list) {
            inner_cid = xqc_list_entry(pos, xqc_cid_inner_t, list);

            if (xqc_cid_is_equal(cid, &inner_cid->cid) == XQC_OK) {
                cid->cid_seq_num = inner_cid->cid.cid_seq_num;
                cid->path_id = inner_cid->cid.path_id;
                return inner_cid;
            }
        }
    }

    return NULL;
}

xqc_cid_inner_t *
xqc_cid_in_cid_set(xqc_cid_set_t *cid_set, xqc_cid_t *cid, uint64_t path_id)
{
    xqc_cid_inner_t *inner_cid = NULL;
    xqc_list_head_t *pos, *next;

    xqc_cid_set_inner_t *inner_set;
    inner_set = xqc_get_path_cid_set(cid_set, path_id);

    if (!inner_set) {
        return NULL;
    }

    xqc_list_for_each_safe(pos, next, &inner_set->cid_list) {
        inner_cid = xqc_list_entry(pos, xqc_cid_inner_t, list);
        if (xqc_cid_is_equal(cid, &inner_cid->cid) == XQC_OK) {
            cid->cid_seq_num = inner_cid->cid.cid_seq_num;
            cid->path_id = inner_cid->cid.path_id;
            return inner_cid;
        }
    }

    return NULL;
}


xqc_int_t
xqc_cid_switch_to_next_state(xqc_cid_set_t *cid_set, xqc_cid_inner_t *cid, xqc_cid_state_t next_state, uint64_t path_id)
{
    if (xqc_cid_in_cid_set(cid_set, &cid->cid, path_id) == NULL) {
        return -XQC_ECONN_CID_NOT_FOUND;
    }

    xqc_cid_state_t current_state = cid->state;

    if (current_state == next_state) {
        return XQC_OK;

    } else if (current_state > next_state) {
        return -XQC_ECID_STATE;
    }

    xqc_cid_set_inner_t *inner_set;
    inner_set = xqc_get_path_cid_set(cid_set, path_id);

    if (!inner_set) {
        return -XQC_ECONN_CID_NOT_FOUND;
    }

    if (current_state == XQC_CID_UNUSED) {
        inner_set->unused_cnt--;
        if (cid->acked == XQC_CID_ACKED) {
            inner_set->acked_unused--;
        }

    } else if (current_state == XQC_CID_USED) {
        inner_set->used_cnt--;

    } else if (current_state == XQC_CID_RETIRED) {
        inner_set->retired_cnt--;
    }

    cid->state = next_state;

    if (next_state == XQC_CID_USED) {
        inner_set->used_cnt++;

    } else if (next_state == XQC_CID_RETIRED) {
        inner_set->retired_cnt++;
    }

    return XQC_OK;
}

xqc_int_t
xqc_get_unused_cid(xqc_cid_set_t *cid_set, xqc_cid_t *cid, uint64_t path_id)
{    
    xqc_cid_set_inner_t *inner_set;
    inner_set = xqc_get_path_cid_set(cid_set, path_id);

    if (!inner_set) {
        return -XQC_ECONN_NO_AVAIL_CID;
    }

    if (inner_set->unused_cnt == 0) {
        return -XQC_ECONN_NO_AVAIL_CID;
    }

    xqc_cid_inner_t *inner_cid;
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &inner_set->cid_list) {
        inner_cid = xqc_list_entry(pos, xqc_cid_inner_t, list);

        if (inner_cid->state == XQC_CID_UNUSED) {
            xqc_cid_copy(cid, &inner_cid->cid);
            return xqc_cid_switch_to_next_state(cid_set, inner_cid, XQC_CID_USED, path_id);
        }
    }

    return -XQC_ECONN_NO_AVAIL_CID;
}

xqc_cid_inner_t *
xqc_get_inner_cid_by_seq(xqc_cid_set_t *cid_set, uint64_t seq_num, uint64_t path_id)
{
    xqc_cid_inner_t *inner_cid = NULL;
    xqc_list_head_t *pos, *next;

    xqc_cid_set_inner_t *inner_set;
    inner_set = xqc_get_path_cid_set(cid_set, path_id);

    if (!inner_set) {
        return NULL;
    }

    xqc_list_for_each_safe(pos, next, &inner_set->cid_list) {
        inner_cid = xqc_list_entry(pos, xqc_cid_inner_t, list);

        if (inner_cid->cid.cid_seq_num == seq_num) {
            return inner_cid;
        }
    }

    return NULL;
}

xqc_int_t 
xqc_cid_set_add_path(xqc_cid_set_t *cid_set, uint64_t path_id)
{
    xqc_cid_set_inner_t *inner_set;
    inner_set = xqc_get_path_cid_set(cid_set, path_id);

    if (inner_set) {
        return XQC_OK;
    }

    /* Note: the memory of inner_set will only be released on conn_destroy */
    inner_set = xqc_calloc(1, sizeof(xqc_cid_set_inner_t));
    if (!inner_set) {
        return -XQC_EMALLOC;
    }

    xqc_cid_set_inner_init(inner_set);
    xqc_list_add_tail(&inner_set->next, &cid_set->cid_set_list);
    inner_set->path_id = path_id;
    cid_set->set_cnt[XQC_CID_SET_UNUSED]++;
    return XQC_OK;
}

void 
xqc_cid_set_update_state(xqc_cid_set_t *cid_set, 
    uint64_t path_id, xqc_cid_set_state_t state)
{
    xqc_cid_set_inner_t *inner_set;
    inner_set = xqc_get_path_cid_set(cid_set, path_id);

    if (inner_set && inner_set->set_state != state) {
        cid_set->set_cnt[inner_set->set_state]--;
        cid_set->set_cnt[state]++;
        inner_set->set_state = state;
    }
}

void 
xqc_cid_set_on_cid_acked(xqc_cid_set_t *cid_set, uint64_t path_id, 
    uint64_t cid_seq)
{
    xqc_cid_set_inner_t *inner_set;
    xqc_list_head_t *pos, *next;
    xqc_cid_inner_t *inner_cid;
    inner_set = xqc_get_path_cid_set(cid_set, path_id);

    if (inner_set) {
        xqc_list_for_each_safe(pos, next, &inner_set->cid_list) {
            inner_cid = xqc_list_entry(pos, xqc_cid_inner_t, list);
            if (inner_cid->cid.cid_seq_num == cid_seq) {
                if (inner_cid->acked == XQC_CID_UNACKED 
                    && inner_cid->state == XQC_CID_UNUSED)
                {
                    inner_set->acked_unused++;
                }
                inner_cid->acked = XQC_CID_ACKED;
            }
        }
    }
}