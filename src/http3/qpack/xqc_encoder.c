/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "src/http3/qpack/xqc_encoder.h"
#include "src/http3/qpack/xqc_ins.h"
#include "src/http3/qpack/xqc_rep.h"


double xqc_encoder_insert_limit_name = 1.0 / 16;
double xqc_encoder_insert_limit_entry = 3.0 / 4;

typedef struct xqc_encoder_s {
    /* dynamic table */
    xqc_dtable_t           *dtable;

    /* capacity of dynamic table */
    size_t                  dtable_cap;

    /*
     * max entry count of dynamic table, this value is calculated by the Max Dynamic Table Capacity
     * specified by decoder, and is remembered here to encode required insert count
     */
    size_t                  max_entries;

    /* unacked field section list. used to protect those entries are still being used */
    xqc_list_head_t         unack_list;
    /* absolute index of the min unacked entry in dynamic table */
    uint64_t                min_unack_index;

    /* known received count. related with blocked streams */
    uint64_t                krc;

    /*
     * blocked streams. used to limit encoder's streams that might be blocked to decoder's
     * SETTINGS_QPACK_BLOCKED_STREAMS parameter. if reached the MAX_BLOCKED_STREAMS limit, encoder
     * will try to refer those entries which are known to avoid adding a new blocked stream
     */
    uint64_t                max_blocked_stream;
    uint64_t                blocked_stream_count;
    xqc_list_head_t         blocked_list;

    /* log handler */
    xqc_log_t              *log;

    /* dtable insertion limit for name. name_len_limit = name_limit * dtable_cap */
    double                  name_limit;
    size_t                  name_len_limit;

    /*
     * dtable insertion limit for entry.
     * insert_limit_entry_size = insert_limit_entry * dtable_cap
     */
    double                  entry_limit;
    size_t                  entry_size_limit;

} xqc_encoder_s;



/* this enum tells strategy of dynamic table insertion and type of encoder insert instruction */
typedef enum xqc_insert_type_s {
    /* no insertion */
    XQC_INSERT_NONE,

    /* name inexist, insert literal name only */
    XQC_INSERT_NAME,

    /* name exists, and insert name and value into dtable */
    XQC_INSERT_NAME_REF_VALUE,

    /* name not found, insert name and value into dtable */
    XQC_INSERT_LITERAL_NAME_VALUE,

} xqc_insert_type_t;


/*
 * the encode information of an header, which will be generated after lookup static or dynamic 
 * tables, check index flag, and check encoding strategy
 */
typedef struct xqc_hdr_enc_rule_s {
    /* pointer to header */
    xqc_http_header_t  *hdr;

    /* table flag, 1 for static table, 0 for dynamic table */
    xqc_flag_t          ref_table;

    /*
     * never index flag. if never flag is set, it means that at least value
     * is encoded as literal, and ref MUST NOT be XQC_NV_REF_NAME_AND_VALUE.
     */
    xqc_flag_t          never;

    /* index mode */
    xqc_nv_ref_type_t   ref;

    /* absolute index of referred entry */
    uint64_t            index;

    /* type of header */
    xqc_hdr_type_t      type;

    /* whether insert entry into dtable */
    xqc_insert_type_t   insertion;

} xqc_hdr_enc_rule_t;


/* field section info, will be generated during preparing encoding */
typedef struct xqc_field_section_s {
    /* base filed in encoded field section */
    uint64_t base;

    /* required insert count */
    uint64_t rqrd_insert_cnt;

    /* min referred entry index of dynamic table */
    uint64_t min_ref_idx;

    /* field line information */
    xqc_hdr_enc_rule_t *reps;
    size_t              rep_cnt;
} xqc_field_section_t;


/* used to record those streams that have not been acked */
typedef struct xqc_encoder_unack_section_s {
    xqc_list_head_t     head;
    uint64_t            stream_id;
    uint64_t            min_rep_index;
    uint64_t            rqrd_insert_cnt;
} xqc_encoder_unack_section_t;


/* used to record those entries that have not been acked and may be blocked */
typedef struct xqc_encoder_blocked_stream_s {
    xqc_list_head_t     head;
    uint64_t            stream_id;
    uint64_t            rqrd_insert_cnt;
} xqc_encoder_blocked_stream_t;


xqc_encoder_unack_section_t *
xqc_encoder_unack_section_create(uint64_t stream_id, uint64_t min_rep_index, uint64_t ricnt)
{
    xqc_encoder_unack_section_t *section = xqc_malloc(sizeof(xqc_encoder_unack_section_t));
    if (section == NULL) {
        return NULL;
    }

    xqc_init_list_head(&section->head);
    section->stream_id = stream_id;
    section->min_rep_index = min_rep_index;
    section->rqrd_insert_cnt = ricnt;
    return section;
}

void
xqc_encoder_unack_section_free(xqc_encoder_unack_section_t *section)
{
    xqc_list_del(&section->head);
    xqc_free(section);
}


xqc_encoder_blocked_stream_t *
xqc_encoder_blocked_stream_create(uint64_t stream_id, uint64_t ricnt)
{
    xqc_encoder_blocked_stream_t *stream = xqc_malloc(sizeof(xqc_encoder_blocked_stream_t));
    if (stream == NULL) {
        return NULL;
    }

    xqc_init_list_head(&stream->head);
    stream->stream_id = stream_id;
    stream->rqrd_insert_cnt = ricnt;
    return stream;
}

void
xqc_encoder_blocked_stream_free(xqc_encoder_blocked_stream_t *stream)
{
    xqc_list_del(&stream->head);
    xqc_free(stream);
}

/* remember a stream that refers entries larger than known received count */
void
xqc_encoder_add_blocked_stream(xqc_encoder_t *enc, uint64_t stream_id, uint64_t ricnt)
{
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &enc->blocked_list) {
        xqc_encoder_blocked_stream_t *stream = 
            xqc_list_entry(pos, xqc_encoder_blocked_stream_t, head);

        if (stream->stream_id == stream_id) {
            /*
             * if stream is already blocked before, but refers larger entries this time,
             * update the required insert count
             */
            if (ricnt > stream->rqrd_insert_cnt) {
                xqc_log(enc->log, XQC_LOG_DEBUG, "|update blocked stream ricnt|id:%ui|ricnt:%ui|"
                        "ori:%ui|", stream->stream_id, ricnt, stream->rqrd_insert_cnt);
                stream->rqrd_insert_cnt = ricnt;
            }

            return;
        }
    }

    /* stream not found, add to blocked list */
    xqc_encoder_blocked_stream_t *stream = xqc_encoder_blocked_stream_create(stream_id, ricnt);
    xqc_list_add_tail(&stream->head, &enc->blocked_list);

    enc->blocked_stream_count++;
}

/* delete blocked streams. this will happen after Insert Increment or Section Acknowledgement */
void
xqc_encoder_unblock_streams(xqc_encoder_t *enc)
{
    xqc_list_head_t *pos, *next;

    xqc_list_for_each_safe(pos, next, &enc->blocked_list) {
        xqc_encoder_blocked_stream_t *stream = 
            xqc_list_entry(pos, xqc_encoder_blocked_stream_t, head);
        if (stream->rqrd_insert_cnt <= enc->krc) {
            xqc_encoder_blocked_stream_free(stream);
            enc->blocked_stream_count--;
        }
    }
}


xqc_encoder_t *
xqc_encoder_create(xqc_log_t *log)
{
    xqc_encoder_t *enc = xqc_malloc(sizeof(xqc_encoder_t));
    if (NULL == enc) {
        return NULL;
    }

    /* init dynamic table */
    enc->dtable = xqc_dtable_create(XQC_QPACK_DEFAULT_HASH_TABLE_SIZE, log);
    if (enc->dtable == NULL) {
        xqc_free(enc);
        return NULL;
    }

    enc->log = log;

    enc->dtable_cap = 0;
    enc->max_entries = 0;

    enc->min_unack_index = XQC_INVALID_INDEX;
    enc->max_blocked_stream = 0;
    enc->blocked_stream_count = 0;
    enc->krc = 0;

    xqc_encoder_set_insert_limit(enc, xqc_encoder_insert_limit_name, 
                                 xqc_encoder_insert_limit_entry);

    xqc_init_list_head(&enc->unack_list);
    xqc_init_list_head(&enc->blocked_list);

    return enc;
}


void
xqc_encoder_destroy(xqc_encoder_t *enc)
{
    if (NULL == enc) {
        return;
    }

    if (enc->dtable) {
        xqc_dtable_free(enc->dtable);
    }

    xqc_list_head_t *pos, *next;

    /* free unacked section */
    xqc_encoder_unack_section_t *section;
    xqc_list_for_each_safe(pos, next, &enc->unack_list) {
        section = xqc_list_entry(pos, xqc_encoder_unack_section_t, head);
        xqc_encoder_unack_section_free(section);
    }

    /* free blocked stream */
    xqc_encoder_blocked_stream_t *stream;
    xqc_list_for_each_safe(pos, next, &enc->blocked_list) {
        stream = xqc_list_entry(pos, xqc_encoder_blocked_stream_t, head);
        xqc_encoder_blocked_stream_free(stream);
    }

    xqc_free(enc);
}


void
xqc_encoder_lookup_nv(xqc_encoder_t *enc, xqc_hdr_enc_rule_t *info)
{
    xqc_http_header_t *hdr = info->hdr;
    unsigned char *name = hdr->name.iov_base;
    size_t nlen = hdr->name.iov_len;
    unsigned char *value = hdr->value.iov_base;
    size_t vlen = hdr->value.iov_len;

    info->type = xqc_h3_hdr_type(name, nlen);

    /* if header is a known header, will try to find in static table */
    uint64_t stable_idx = XQC_INVALID_INDEX;
    xqc_nv_ref_type_t stable_ref = XQC_NV_REF_NONE;
    if (info->type < XQC_HDR_STATIC_TABLE_END) {
        stable_ref = xqc_stable_lookup(name, nlen, value, vlen, info->type, &stable_idx);
    }

    /* not whole matched in stable, try to lookup dtable */
    uint64_t dtable_idx = XQC_INVALID_INDEX;
    xqc_nv_ref_type_t dtable_ref = XQC_NV_REF_NONE;
    if (stable_ref != XQC_NV_REF_NAME_AND_VALUE) {
        dtable_ref = xqc_dtable_lookup(enc->dtable, name, nlen, value, vlen, &dtable_idx);
    }

    if (stable_ref != XQC_NV_REF_NONE || dtable_ref != XQC_NV_REF_NONE) {
        /* static table if always preferred than dynamic table. as it won't be blocked */
        if (stable_ref >= dtable_ref) {
            info->ref_table = XQC_STABLE_FLAG;
            info->ref = stable_ref;
            info->index = stable_idx;

        } else {
            info->ref_table = XQC_DTABLE_FLAG;
            info->ref = dtable_ref;
            info->index = dtable_idx;
        }
    }
}


xqc_bool_t
xqc_encoder_never_idx_value_hdr(xqc_hdr_enc_rule_t* info)
{
    if (info->hdr->flags & XQC_HTTP_HEADER_FLAG_NEVER_INDEX_VALUE) {
        return XQC_TRUE;
    }

    /* check header type, some headers are more appropriate to be never indexed */
    switch (info->type) {
    case XQC_HDR_AUTHORIZATION:
        return XQC_TRUE;

    case XQC_HDR_COOKIE:
        if (info->hdr->value.iov_len < 20) {
            return XQC_TRUE;
        }
        break;

    default:
        break;
    }

    return XQC_FALSE;
}


/* check if do insertion will violate the max blocked streams limit */
xqc_bool_t
xqc_encoder_check_block_stream_limit(xqc_encoder_t *enc, uint64_t stream_id)
{
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &enc->blocked_list) {
        xqc_encoder_blocked_stream_t *bs = 
            xqc_list_entry(pos, xqc_encoder_blocked_stream_t, head);
        if (bs->stream_id == stream_id) {
            /*
             * the stream is already blocked, won't increase new blocked stream,
             * so it can insert entries into dtable
             */
            return XQC_FALSE;
        }
    }

    /* stream_id not found, blocked_stream_count + 1 shall not exceed max_blocked_stream */
    return enc->blocked_stream_count >= enc->max_blocked_stream;
}


/* check if insertion is possible */
xqc_bool_t
xqc_encoder_check_insert(xqc_encoder_t *enc, xqc_hdr_enc_rule_t *info, xqc_bool_t blocked)
{
    /* if peer's Max Dynamic Table Capacity is not known, try no dynamic table insertion */
    if (enc->max_entries == 0) {
        return XQC_FALSE;
    }

    /* check if this stream can be blocked */
    if (blocked == XQC_FALSE) {
        /* if this stream won't violate the blocked stream limit, insertion is possible */
        return XQC_TRUE;
    }

    /*
     * when blocked, refer an entry in dtable with index larger than known received count,
     * might increase the blocked stream count on decoder, it's better send with literal
     */
    if (info->ref_table == XQC_DTABLE_FLAG && info->ref != XQC_NV_REF_NONE
        && info->index >= enc->krc)
    {
        /* when blocked, it's better not refer an entry with index larger than krc */
        xqc_log(enc->log, XQC_LOG_DEBUG, "|dtable shall not return an entry with index >= krc|");
        info->ref = XQC_NV_REF_NONE;
        info->index = XQC_INVALID_INDEX;
    }

    /* insertion is impossible when blocked */
    return XQC_FALSE;
}


void
xqc_encoder_check_never_value_index_mode(xqc_encoder_t *enc, xqc_hdr_enc_rule_t* info,
    xqc_bool_t blocked)
{
    /* decide insertion mode for headers of which only name can be indexed at most */
    info->never = 1;

    /* check if insertion is possible */
    if (xqc_encoder_check_insert(enc, info, blocked) == XQC_FALSE) {
        return;
    }

    /*
     * though never is set, but we can try to insert name into dtable and refer it. that is
     * Literal Field Line With Name Reference with never bit set to 1
     */
    if (info->ref == XQC_NV_REF_NONE) {
        if (info->hdr->name.iov_len <= enc->name_len_limit) {
            info->insertion = XQC_INSERT_NAME;
        }
    }
}

void
xqc_encoder_check_normal_index_mode(xqc_encoder_t *enc, xqc_hdr_enc_rule_t *info,
    xqc_bool_t blocked)
{
    /* check if insertion is possible */
    if (xqc_encoder_check_insert(enc, info, blocked) == XQC_FALSE) {
        return;
    }

    /* continue to check insertion */
    size_t esz = xqc_dtable_entry_size(info->hdr->name.iov_len, info->hdr->value.iov_len);

    /* decide insertion mode according to lookup results */
    switch (info->ref) {
    case XQC_NV_REF_NONE:
        /* no entry found, try to add one in dtable */
        if (info->hdr->name.iov_len <= enc->name_len_limit) {
            if (esz <= enc->entry_size_limit) {
                info->insertion = XQC_INSERT_LITERAL_NAME_VALUE;

            } else {
                info->insertion = XQC_INSERT_NAME;
            }
        }
        break;

    case XQC_NV_REF_NAME:
        /*
         * if name is referred in dtable, will try to decide whether an insertion with
         * value is worthy, with a more aggressive size restriction
         */
        if (esz <= enc->entry_size_limit /* && info->ref_table == XQC_DTABLE_FLAG */) {
            info->insertion = XQC_INSERT_NAME_REF_VALUE;
        }
        break;

    default:
        break;
    }
}

/*
 * decide the index mode of headers, based on the lookup result from stable and dtable.
 * never-indexed filed line is returned directly before
 */
void 
xqc_encoder_check_index_mode(xqc_encoder_t *enc, xqc_hdr_enc_rule_t *info, xqc_bool_t blocked)
{
    info->insertion = XQC_INSERT_NONE;

    if (xqc_encoder_never_idx_value_hdr(info)) {
        xqc_encoder_check_never_value_index_mode(enc, info, blocked);

    } else {
        xqc_encoder_check_normal_index_mode(enc, info, blocked);
    }
}


xqc_int_t
xqc_encoder_write_insert_ins(xqc_encoder_t *enc, xqc_var_buf_t *ins, xqc_hdr_enc_rule_t *info,
    uint64_t base_idx)
{
    xqc_int_t ret = XQC_OK;
    struct iovec *name = &info->hdr->name;
    struct iovec *value = &info->hdr->value;

    switch (info->insertion) {
    case XQC_INSERT_NAME:
        /* insert only name will help to reduce the cost of dtable capacity */
        ret = xqc_ins_write_insert_literal_name(ins, name->iov_base, name->iov_len, NULL, 0);
        xqc_log_event(enc->log, QPACK_INSTRUCTION_CREATED, XQC_LOG_ENCODER_EVENT,
                      XQC_INS_TYPE_ENC_INSERT_LITERAL, name->iov_len, name->iov_base, 0, NULL);
        break;

    case XQC_INSERT_NAME_REF_VALUE: {
        uint64_t idx = (info->ref_table == XQC_DTABLE_FLAG
                        ? xqc_abs2brel(base_idx, info->index) : info->index);
        ret = xqc_ins_write_insert_name_ref(ins, info->ref_table, idx,
                                            value->iov_base, value->iov_len);
        xqc_log_event(enc->log, QPACK_INSTRUCTION_CREATED, XQC_LOG_ENCODER_EVENT,
                      XQC_INS_TYPE_ENC_INSERT_NAME_REF, info->ref_table, idx,
                      value->iov_len, value->iov_base);
        break;
    }

    case XQC_INSERT_LITERAL_NAME_VALUE:
        ret = xqc_ins_write_insert_literal_name(ins, name->iov_base, name->iov_len,
                                                value->iov_base, value->iov_len);
        xqc_log_event(enc->log, QPACK_INSTRUCTION_CREATED, XQC_LOG_ENCODER_EVENT,
                      XQC_INS_TYPE_ENC_INSERT_LITERAL, name->iov_len, name->iov_base,
                      value->iov_len, value->iov_base);
        break;

    default:
        return ret;
    }

    xqc_log_event(enc->log, QPACK_STATE_UPDATED, XQC_LOG_ENCODER_EVENT, enc->dtable, enc->krc);
    return ret;
}


/* insert entry into dynamic table */
xqc_int_t
xqc_encoder_insert(xqc_encoder_t *enc, xqc_hdr_enc_rule_t *info, xqc_var_buf_t *ins)
{
    uint64_t idx = XQC_INVALID_INDEX;
    uint64_t base_idx = xqc_dtable_get_insert_cnt(enc->dtable);
    xqc_int_t ret = XQC_OK;

    switch (info->insertion) {
    case XQC_INSERT_NAME:
        ret = xqc_dtable_add(enc->dtable, info->hdr->name.iov_base, info->hdr->name.iov_len,
                             NULL, 0, &idx);
        break;

    case XQC_INSERT_NAME_REF_VALUE:
    case XQC_INSERT_LITERAL_NAME_VALUE:
        ret = xqc_dtable_add(enc->dtable, info->hdr->name.iov_base, info->hdr->name.iov_len,
                             info->hdr->value.iov_base, info->hdr->value.iov_len, &idx);
        break;

    default:
        return XQC_OK;
    }

    if (ret != XQC_OK) {
        /* if insertion is failed, will try send as lookup result */
        info->insertion = XQC_INSERT_NONE;
        xqc_log(enc->log, XQC_LOG_INFO, "|insertion failed|ret:%d|", ret);
        return XQC_OK;  /* insertion failure is OK */
    }

    ret = xqc_encoder_write_insert_ins(enc, ins, info, base_idx);
    if (ret != XQC_OK) {
        xqc_log(enc->log, XQC_LOG_ERROR, "|write insertion ins failed|ret:%d|", ret);
        return ret;
    }

    /*
     * ref mode and index CAN ONLY BE adjusted after insertion success. it may act as downgrade if
     * name was found in dtable or stable, but insertion fails
     */
    info->ref_table = XQC_DTABLE_FLAG;
    info->ref = info->insertion == XQC_INSERT_NAME ? XQC_NV_REF_NAME : XQC_NV_REF_NAME_AND_VALUE;
    info->index = idx;

    return XQC_OK;
}


xqc_int_t
xqc_encoder_try_duplicate(xqc_encoder_t *enc, xqc_hdr_enc_rule_t *info, xqc_var_buf_t *ins)
{
    xqc_int_t ret = XQC_OK;
    xqc_bool_t draining = XQC_FALSE;
    uint64_t base_index = xqc_dtable_get_insert_cnt(enc->dtable);

    /* check if the referred entry is draining */
    ret = xqc_dtable_is_entry_draining(enc->dtable, info->index, &draining);
    if (ret != XQC_OK) {
        xqc_log(enc->log, XQC_LOG_ERROR, "|check entry draining error|ret:%d|", ret);
        return ret;
    }

    if (draining == XQC_TRUE) {
        uint64_t dup_idx;
        ret = xqc_dtable_duplicate(enc->dtable, info->index, &dup_idx);
        if (ret != XQC_OK) {
            xqc_log(enc->log, XQC_LOG_INFO, "|duplicate entry fail|ret:%d|", ret);
            return ret;
        }

        /* write duplicate instruction */
        ret = xqc_ins_write_dup(ins, xqc_abs2brel(base_index, info->index));
        if (ret != XQC_OK) {
            xqc_log(enc->log, XQC_LOG_ERROR, "|write duplicate instruction error|ret:%d|", ret);
            return ret;
        }
        xqc_log_event(enc->log, QPACK_INSTRUCTION_CREATED, XQC_LOG_ENCODER_EVENT,
                      XQC_INS_TYPE_ENC_DUP, info->index);

        /* 
         * change info->index until duplicate success, if it fails, will do
         * as lookup result. cause peer shall receive encoder ins sequentially,
         * pop of duplicated entry during subsequent operations will always 
         * follow duplicate instruction and thus makes it safe on decoder 
         */
        info->index = dup_idx;
    }

    return XQC_OK;
}


/* refer a header in static table and dynamic table, and generate representation info */
xqc_int_t
xqc_encoder_prepare(xqc_encoder_t *enc, xqc_http_headers_t *hdrs, xqc_field_section_t *fs,
    xqc_var_buf_t *ins, uint64_t stream_id)
{
    xqc_int_t ret = XQC_OK;

    /* check if reached the block stream limit */
    xqc_bool_t limited = xqc_encoder_check_block_stream_limit(enc, stream_id);

    for (size_t i = 0; i < hdrs->count; i++) {
        xqc_http_header_t *hdr = &hdrs->headers[i];
        xqc_hdr_enc_rule_t *info = &fs->reps[i];
        info->hdr = hdr;

        /*
         * if XQC_HTTP_HEADER_FLAG_NEVER_INDEX is set, header will be sent as Literal Filed Line
         * With Literal Name, regardless of lookup or insertion operation with stable and dtable
         */
        if (hdr->flags & XQC_HTTP_HEADER_FLAG_NEVER_INDEX) {
            info->ref = XQC_NV_REF_NONE;
            info->never = 1;
            continue;
        }

        /* lookup nv from static table and dynamic table */
        xqc_encoder_lookup_nv(enc, info);

        /* decide dynamic table strategy, including never flag and insertion */
        xqc_encoder_check_index_mode(enc, info, limited);

        /* either insert or duplicate, prepare for dtable entry reference */
        if (info->insertion != XQC_INSERT_NONE) {
            ret = xqc_encoder_insert(enc, info, ins);
            if (ret != XQC_OK) {
                xqc_log(enc->log, XQC_LOG_INFO, "|insertion failed|");
                return ret;
            }

        } else {
            /* when insertion is not limited, and refers and dtable entry, try to duplicate */
            if (limited == XQC_FALSE && info->ref != XQC_NV_REF_NONE
                && info->ref_table == XQC_DTABLE_FLAG)
            {
                /* check and do duplicate, if it fails, send as lookup result */
                ret = xqc_encoder_try_duplicate(enc, info, ins);
                if (ret != XQC_OK) {
                    xqc_log(enc->log, XQC_LOG_INFO, "|try duplicate failed|");
                }
            }
        }

        /* update min dtable referred index */
        if (info->ref != XQC_NV_REF_NONE && info->ref_table == XQC_DTABLE_FLAG
            && info->index < fs->min_ref_idx)
        {
            fs->min_ref_idx = info->index;

            /* if new insertion will generate a lower bound, set the min_ref of dtable */
            if (fs->min_ref_idx < enc->min_unack_index) {
                ret = xqc_dtable_set_min_ref(enc->dtable, info->index);
                if (ret != XQC_OK) {
                    xqc_log(enc->log, XQC_LOG_ERROR, "|set min ref error|");
                    return ret;
                }
            }
        }

        /* update required insert count */
        if (info->ref != XQC_NV_REF_NONE && info->ref_table == XQC_DTABLE_FLAG
            && fs->rqrd_insert_cnt < info->index + 1)
        {
            fs->rqrd_insert_cnt = info->index + 1;
        }
    }

    return XQC_OK;
}


static inline xqc_field_section_t *
xqc_encoder_create_fs_info(size_t hdr_cnt)
{
    xqc_field_section_t *fs = xqc_calloc(1, sizeof(xqc_field_section_t));
    if (NULL == fs) {
        return NULL;
    }

    fs->reps = xqc_calloc(hdr_cnt, sizeof(xqc_hdr_enc_rule_t));
    if (NULL == fs->reps) {
        xqc_free(fs);
        return NULL;
    }

    fs->rep_cnt = hdr_cnt;
    fs->min_ref_idx = XQC_INVALID_INDEX; /* initialized to be max */

    return fs;
}


static inline void
xqc_encoder_free_fs_info(xqc_field_section_t *fs)
{
    xqc_free(fs->reps);
    xqc_free(fs);
}


xqc_int_t
xqc_encoder_write_efs(xqc_encoder_t *enc, xqc_field_section_t *fs, xqc_var_buf_t *buf)
{
    /* write prefix */
    xqc_int_t ret = xqc_rep_write_prefix(buf, enc->max_entries, fs->rqrd_insert_cnt, fs->base);
    if (ret < 0) {
        xqc_log(enc->log, XQC_LOG_ERROR, "|write field section prefix error|ret:%d|", ret);
        return ret;
    }
    xqc_log(enc->log, XQC_LOG_DEBUG, "|write field section prefix|ricnt:%d|base:%d|",
            fs->rqrd_insert_cnt, fs->base);
    xqc_log_event(enc->log, QPACK_HEADERS_ENCODED, XQC_LOG_BLOCK_PREFIX,
                  fs->rqrd_insert_cnt, fs->base);

    uint64_t idx = XQC_INVALID_INDEX;
    xqc_bool_t pb = XQC_FALSE;

    /* write field lines */
    for (size_t i = 0; i < fs->rep_cnt; i++) {
        xqc_hdr_enc_rule_t *info = &fs->reps[i];

        /* calculate field line index and dynamic table post-base */
        if (info->ref_table == XQC_DTABLE_FLAG) {
            if (info->index >= fs->base) {
                idx = xqc_abs2pbrel(fs->base, info->index);
                pb = XQC_TRUE;

            } else {
                idx = xqc_abs2brel(fs->base, info->index);
                pb = XQC_FALSE;
            }

        } else {
            idx = info->index;
            pb = XQC_FALSE;
        }

        if (info->ref == XQC_NV_REF_NONE) {
            ret = xqc_rep_write_literal_name_value(buf, info->never, info->hdr->name.iov_len,
                                                   info->hdr->name.iov_base, info->hdr->value.iov_len,
                                                   info->hdr->value.iov_base);
            xqc_log(enc->log, XQC_LOG_DEBUG, "|write literal_name_value|");
            xqc_log_event(enc->log, QPACK_HEADERS_ENCODED, XQC_LOG_HEADER_BLOCK,
                          XQC_REP_TYPE_LITERAL, info);

        } else if (info->ref == XQC_NV_REF_NAME) {
            if (pb == XQC_TRUE) {
                ret = xqc_rep_write_literal_with_pb_name_ref(buf, info->never, idx,
                                                             info->hdr->value.iov_len,
                                                             info->hdr->value.iov_base);
                xqc_log(enc->log, XQC_LOG_DEBUG, "|write literal_with_pb_name_ref|index:%d|", idx);
                xqc_log_event(enc->log, QPACK_HEADERS_ENCODED, XQC_LOG_HEADER_BLOCK,
                              XQC_REP_TYPE_POST_BASE_NAME_REFERENCE, info, idx);

            } else {
                ret = xqc_rep_write_literal_with_name_ref(buf, info->never, info->ref_table, idx,
                                                          info->hdr->value.iov_len,
                                                          info->hdr->value.iov_base);
                xqc_log(enc->log, XQC_LOG_DEBUG, "|write literal_with_name_ref|index:%d|", idx);
                xqc_log_event(enc->log, QPACK_HEADERS_ENCODED, XQC_LOG_HEADER_BLOCK,
                              XQC_REP_TYPE_NAME_REFERENCE, info, idx);
            }

        } else {
            if (pb == XQC_TRUE) {
                ret = xqc_rep_write_indexed_pb(buf, idx);
                xqc_log(enc->log, XQC_LOG_DEBUG, "|write indexed_pb|index:%d|", idx);
                xqc_log_event(enc->log, QPACK_HEADERS_ENCODED, XQC_LOG_HEADER_BLOCK,
                              XQC_REP_TYPE_POST_BASE_INDEXED, info, idx);

            } else {
                ret = xqc_rep_write_indexed(buf, info->ref_table, idx);
                xqc_log(enc->log, XQC_LOG_DEBUG, "|write indexed|index:%d|", idx);
                xqc_log_event(enc->log, QPACK_HEADERS_ENCODED, XQC_LOG_HEADER_BLOCK,
                              XQC_REP_TYPE_INDEXED, info, idx);
            }
        }

        if (ret < 0) {
            xqc_log(enc->log, XQC_LOG_ERROR, "|write field line error|ret:%d|ref:%d|pb:%d|", ret,
                    info->ref, pb);
            return ret;
        }
    }

    return XQC_OK;
}


/* remember unacked field section, used to check which entries are still referred */
static inline xqc_int_t
xqc_encoder_save_unacked(xqc_encoder_t *enc, uint64_t stream_id, xqc_field_section_t *fs)
{
    uint64_t min_unack_idx_ori = enc->min_unack_index;

    if (fs->rqrd_insert_cnt != 0) {
        xqc_encoder_unack_section_t *section = 
            xqc_encoder_unack_section_create(stream_id, fs->min_ref_idx, fs->rqrd_insert_cnt);
        if (section == NULL) {
            xqc_log(enc->log, XQC_LOG_ERROR, "|create unack section error|");
            return -XQC_EMALLOC;
        }

        /* add to the end of unack list, with the same sequence of sections */
        xqc_list_add_tail(&section->head, &enc->unack_list);
        if (fs->min_ref_idx < enc->min_unack_index) {
            /* refresh min referred index */
            enc->min_unack_index = fs->min_ref_idx;
        }
    }

    return XQC_OK;
}


xqc_int_t
xqc_encoder_enc_headers(xqc_encoder_t *enc, xqc_var_buf_t *efs,
    xqc_var_buf_t *ins, uint64_t stream_id, xqc_http_headers_t *hdrs)
{
    if (hdrs->count == 0) {
        xqc_log(enc->log, XQC_LOG_WARN, "|input empty headers|");
        return XQC_OK;
    }

    xqc_field_section_t *fs = xqc_encoder_create_fs_info(hdrs->count);
    if (NULL == fs) {
        xqc_log(enc->log, XQC_LOG_ERROR, "|create field section info error|");
        return -XQC_EMALLOC;
    }
    fs->base = xqc_dtable_get_insert_cnt(enc->dtable);

    /* prepare for write buffer, lookup nv, do dtable insertion, decide indexing mode */
    xqc_int_t ret = xqc_encoder_prepare(enc, hdrs, fs, ins, stream_id);
    if (ret != XQC_OK) {
        xqc_log(enc->log, XQC_LOG_ERROR, "|prepare write field section error|ret:%d|", ret);
        goto fail;
    }

    /* write encoded field section */
    ret = xqc_encoder_write_efs(enc, fs, efs);
    if (ret != XQC_OK) {
        xqc_log(enc->log, XQC_LOG_ERROR, "|write field section error|ret:%d|", ret);
        goto fail;
    }

    /* save representation info */
    ret = xqc_encoder_save_unacked(enc, stream_id, fs);
    if (ret != XQC_OK) {
        xqc_log(enc->log, XQC_LOG_ERROR, "|save unacked error|ret:%d|", ret);
        goto fail;
    }

    /* required insert count is larger than known received count, take it as blocked stream */
    if (fs->rqrd_insert_cnt > enc->krc) {
        xqc_encoder_add_blocked_stream(enc, stream_id, fs->rqrd_insert_cnt);
    }

fail:

    xqc_encoder_free_fs_info(fs);
    return ret;
}


xqc_int_t
xqc_encoder_section_ack(xqc_encoder_t *enc, uint64_t stream_id)
{
    xqc_log(enc->log, XQC_LOG_DEBUG, "|on section ack|stream_id:%d|", stream_id);

    xqc_list_head_t *pos, *next;
    xqc_encoder_unack_section_t *section;
    xqc_bool_t found = XQC_FALSE;
    enc->min_unack_index = XQC_INVALID_INDEX;   /* set it to max first */

    xqc_list_for_each_safe(pos, next, &enc->unack_list) {
        section = xqc_list_entry(pos, xqc_encoder_unack_section_t, head);

        /* find the unacked section, and delete it from unack_list */
        if (found == XQC_FALSE && section->stream_id == stream_id) {
            found = XQC_TRUE;
            /*
             * if section acked, and this section's required insert count is larger than current
             * known rcvd cnt, it means that decoder received those headers and acked them
             */
            if (section->rqrd_insert_cnt > enc->krc) {
                enc->krc = section->rqrd_insert_cnt;
                xqc_encoder_unblock_streams(enc);
            }

            xqc_log(enc->log, XQC_LOG_DEBUG, "|section acked|stream_id:%ui|min_rep:%ui|ricnt:%ui|",
                    stream_id, section->min_rep_index, section->rqrd_insert_cnt);

            /* delete section record */
            xqc_encoder_unack_section_free(section);
            continue;
        }

        /* adjust the min_unack_index, incase the delete section has referred the min index */
        if (section->min_rep_index != XQC_INVALID_INDEX
            && (enc->min_unack_index == XQC_INVALID_INDEX
                || section->min_rep_index < enc->min_unack_index))
        {
            enc->min_unack_index = section->min_rep_index;
        }

        xqc_log(enc->log, XQC_LOG_DEBUG, "|unacked stream|stream_id:%ui|min_rep:%ui|ricnt:%ui|"
                "unacked_stream_id:%ui|", stream_id, section->min_rep_index, 
                section->rqrd_insert_cnt, section->stream_id);
    }

    if (found == XQC_FALSE) {
        xqc_log(enc->log, XQC_LOG_ERROR, "|section not found|stream_id:%ui|", stream_id);
        return XQC_ERROR;

    }

    xqc_int_t ret = xqc_dtable_set_min_ref(enc->dtable, enc->min_unack_index);
    if (ret != XQC_OK) {
        xqc_log(enc->log, XQC_LOG_ERROR, "|increase min ref error|ret:%d|", ret);
        return ret;
    }

    return XQC_OK;
}


xqc_int_t
xqc_encoder_cancel_stream(xqc_encoder_t *enc, uint64_t stream_id)
{
    xqc_log(enc->log, XQC_LOG_DEBUG, "|on stream cancel|stream_id:%d|", stream_id);

    xqc_list_head_t *pos, *next;
    enc->min_unack_index = XQC_INVALID_INDEX;

    /* delete from unacked field section list */
    xqc_list_for_each_safe(pos, next, &enc->unack_list) {
        xqc_encoder_unack_section_t *section =
            xqc_list_entry(pos, xqc_encoder_unack_section_t, head);

        if (section->stream_id == stream_id) {
            xqc_log(enc->log, XQC_LOG_DEBUG, "|stream cancel|stream_id:%ui|min_rep:%ui|ricnt:%ui|",
                    stream_id, section->min_rep_index, section->rqrd_insert_cnt);

            /*
             * delete section record, there might be two HEADERS frame in one stream if there is a
             * trailer header
             */
            xqc_encoder_unack_section_free(section);
            continue;
        }

        /* find the min referred index after delete unacked */
        if (section->min_rep_index != XQC_INVALID_INDEX
            && (enc->min_unack_index == XQC_INVALID_INDEX
                || section->min_rep_index < enc->min_unack_index))
        {
            enc->min_unack_index = section->min_rep_index;
        }
    }

    /* update min refer entry in dtable */
    xqc_int_t ret = xqc_dtable_set_min_ref(enc->dtable, enc->min_unack_index);
    if (ret != XQC_OK) {
        xqc_log(enc->log, XQC_LOG_ERROR, "|update min ref error|idx:%ui|stream:%ui|",
                enc->min_unack_index, stream_id);
        return ret;
    }

    /* delete from blocked stream list */
    xqc_list_for_each_safe(pos, next, &enc->blocked_list) {
        xqc_encoder_blocked_stream_t *stream = 
            xqc_list_entry(pos, xqc_encoder_blocked_stream_t, head);

        if (stream->stream_id == stream_id) {
            xqc_encoder_blocked_stream_free(stream);
            enc->blocked_stream_count--;
            break;
        }
    }

    return XQC_OK;
}


xqc_int_t
xqc_encoder_increase_known_rcvd_count(xqc_encoder_t *enc, uint64_t increment)
{
    xqc_log(enc->log, XQC_LOG_DEBUG, "|on insert count increment|increment:%d|", increment);

    if (increment == 0) {
        xqc_log(enc->log, XQC_LOG_ERROR, "|increment equal 0||");
        return -QPACK_DECODER_STREAM_ERROR;
    }

    enc->krc += increment;
    if (enc->krc > xqc_dtable_get_insert_cnt(enc->dtable)) {
        xqc_log(enc->log, XQC_LOG_ERROR, "|krc larger than insert count|krc:%ui|increment:%ui|"
                "icnt:%ui|", enc->krc, increment, xqc_dtable_get_insert_cnt(enc->dtable));
        return -QPACK_DECODER_STREAM_ERROR;
    }

    /* unblock streams */
    xqc_encoder_unblock_streams(enc);

    return XQC_OK;
}


static inline void
xqc_encoder_update_insert_len_limit(xqc_encoder_t *enc)
{
    enc->name_len_limit = enc->dtable_cap * enc->name_limit;
    enc->entry_size_limit = enc->dtable_cap * enc->entry_limit;
}


xqc_int_t
xqc_encoder_set_dtable_cap(xqc_encoder_t *enc, size_t cap)
{
    xqc_int_t ret = xqc_dtable_set_capacity(enc->dtable, cap);
    if (ret == XQC_OK) {
        enc->dtable_cap = cap;
        xqc_encoder_update_insert_len_limit(enc);

    } else {
        xqc_log(enc->log, XQC_LOG_ERROR, "|set dtable cap error|ret:%d|cap:%ui|", ret, cap);
    }

    return ret;
}


void
xqc_encoder_set_insert_limit(xqc_encoder_t *enc, double nlimit, double elimit)
{
    enc->name_limit = nlimit;
    enc->entry_limit = elimit;
    xqc_encoder_update_insert_len_limit(enc);
}


xqc_int_t
xqc_encoder_set_max_dtable_cap(xqc_encoder_t *enc, size_t max_cap)
{
    if (enc->max_entries != 0) {
        xqc_log(enc->log, XQC_LOG_ERROR, "|max dtable cap shall be set only once|");
        return -XQC_QPACK_STATE_ERROR;
    }

    /* actually, what encoder cares about is max_entries */
    enc->max_entries = xqc_dtable_max_entry_cnt(max_cap);

    return XQC_OK;
}


xqc_int_t
xqc_encoder_set_max_blocked_stream(xqc_encoder_t *enc, size_t max_blocked_stream)
{
    enc->max_blocked_stream = max_blocked_stream;
    return XQC_OK;
}

void
xqc_log_QPACK_HEADERS_ENCODED_callback(xqc_log_t *log, const char *func, ...)
{
    va_list args;
    va_start(args, func);
    xqc_int_t type = va_arg(args, xqc_int_t);
    if (type == XQC_LOG_BLOCK_PREFIX) {
        uint64_t ricnt = va_arg(args, uint64_t);
        uint64_t base = va_arg(args, uint64_t);
        xqc_log_implement(log, QPACK_HEADERS_ENCODED, func,
                          "|prefix|ricnt:%ui|base:%ui|", ricnt, base);

    } else if (type == XQC_LOG_HEADER_BLOCK) {
        xqc_rep_type_t rep_type = va_arg(args, xqc_rep_type_t);
        switch (rep_type) {
        case XQC_REP_TYPE_INDEXED:
        case XQC_REP_TYPE_POST_BASE_INDEXED: {
            xqc_hdr_enc_rule_t *info = va_arg(args, xqc_hdr_enc_rule_t *);
            uint64_t index = va_arg(args, uint64_t);
            xqc_flag_t pb = rep_type == XQC_REP_TYPE_POST_BASE_INDEXED;
            xqc_log_implement(log, QPACK_HEADERS_ENCODED, func,
                              "|header|indexed field line|%s%s|index:%ui|",
                              info->ref_table == XQC_DTABLE_FLAG ? "dtable" : "stable",
                              pb ? "" : "|post base", index);
            break;
        }

        case XQC_REP_TYPE_NAME_REFERENCE:
        case XQC_REP_TYPE_POST_BASE_NAME_REFERENCE: {
            xqc_hdr_enc_rule_t *info = va_arg(args, xqc_hdr_enc_rule_t *);
            uint64_t index = va_arg(args, uint64_t);
            xqc_flag_t pb = rep_type == XQC_REP_TYPE_POST_BASE_NAME_REFERENCE;
            xqc_log_implement(log, QPACK_HEADERS_ENCODED, func,
                              "|header|literal with name reference|%s%s|index:%ui|value:%*s|",
                              info->ref_table == XQC_DTABLE_FLAG ? "dtable" : "stable",
                              pb ? "" : "|post base", index,
                              (size_t) info->hdr->value.iov_len, info->hdr->value.iov_base);
            break;
        }

        case XQC_REP_TYPE_LITERAL: {
            xqc_hdr_enc_rule_t *info = va_arg(args, xqc_hdr_enc_rule_t *);
            if (info->hdr->value.iov_len > 0) {
                xqc_log_implement(log, QPACK_HEADERS_ENCODED, func,
                                  "|header|literal|name:%*s|value:%*s|",
                                  (size_t) info->hdr->name.iov_len, info->hdr->name.iov_base,
                                  (size_t) info->hdr->value.iov_len, info->hdr->value.iov_base);
            } else {
                xqc_log_implement(log, QPACK_HEADERS_ENCODED, func,
                                  "|header|literal|name:%*s|",
                                  (size_t) info->hdr->name.iov_len, info->hdr->name.iov_base);
            }
            break;
        }

        default:
            break;
        }

    } else {
        uint64_t stream_id = va_arg(args, uint64_t);
        uint64_t length = va_arg(args, uint64_t);
        xqc_log_implement(log, QPACK_HEADERS_ENCODED, func,
                          "|frame|stream_id:%ui|length:%ui|", stream_id, length);
    }
    va_end(args);
}
