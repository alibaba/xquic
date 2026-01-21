#include "moq/moq_transport/xqc_moq_track.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_message.h"
#include "moq/moq_media/xqc_moq_catalog.h"
#include "moq/moq_media/xqc_moq_datachannel.h"
#include "moq/moq_media/xqc_moq_media_track.h"

#define XQC_MOQ_TRACK_FULL_NAME_BUF_SIZE (XQC_MOQ_MAX_NAME_LEN * 2 + 2)

static void
xqc_moq_track_finalize_destroy(xqc_moq_track_t *track)
{
    if (track == NULL) {
        return;
    }

    track->track_ops.on_destroy(track);
    xqc_moq_track_free_fields(track);
    xqc_free(track);
}

xqc_moq_track_t *
xqc_moq_track_create(xqc_moq_session_t *session, char *track_namespace, char *track_name,
    xqc_moq_track_type_t track_type, xqc_moq_selection_params_t *params, xqc_moq_container_t container, xqc_moq_track_role_t role)
{
    if (session == NULL || track_namespace == NULL || track_name == NULL) {
        return NULL;
    }

    xqc_moq_track_ns_field_t namespace_tuple[1];
    namespace_tuple[0].data = (unsigned char *)track_namespace;
    namespace_tuple[0].len = strlen(track_namespace);

    // Compatibility: string namespace is treated as a single tuple element. 
    return xqc_moq_track_create_with_namespace_tuple(session,
        1, namespace_tuple, track_name, track_type, params, container, role);
}

xqc_moq_track_t *
xqc_moq_track_create_with_namespace_tuple(xqc_moq_session_t *session,
    uint64_t track_namespace_num, const xqc_moq_track_ns_field_t *track_namespace_tuple,
    char *track_name, xqc_moq_track_type_t track_type, xqc_moq_selection_params_t *params,
    xqc_moq_container_t container, xqc_moq_track_role_t role)
{
    xqc_moq_track_t *track;
    xqc_list_head_t *list;

    if (track_namespace_tuple == NULL || track_namespace_num == 0 || track_name == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|NULL ptr|");
        return NULL;
    }

    if (track_namespace_num > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS) {
        xqc_log(session->log, XQC_LOG_ERROR, "|namespace tuple too large|track_namespace_num:%ui|",
                track_namespace_num);
        return NULL;
    }

    track = xqc_moq_find_track_by_track_namespace_tuple(session, track_namespace_tuple,
                                                  track_namespace_num, track_name, role);
    if (track) {
        return track;
    }

    switch (track_type) {
        case XQC_MOQ_TRACK_VIDEO:
        case XQC_MOQ_TRACK_AUDIO:
            track = xqc_calloc(1, sizeof(xqc_moq_media_track_t));
            track->track_ops = xqc_moq_media_track_ops;
            break;
        case XQC_MOQ_TRACK_DATACHANNEL:
            track = xqc_calloc(1, sizeof(xqc_moq_dc_track_t));
            track->track_ops = xqc_moq_datachannel_track_ops;
            break;
        case XQC_MOQ_TRACK_CATALOG:
            track = xqc_calloc(1, sizeof(xqc_moq_catalog_track_t));
            track->track_ops = xqc_moq_catalog_track_ops;
            break;
        default:
            xqc_log(session->log, XQC_LOG_ERROR, "|unknown type|");
            return NULL;
    }

    if (params) {
        xqc_moq_track_copy_params(&track->track_info.selection_params, params);
    }
    track->session = session;
    track->track_info.track_type = track_type;
    track->container_format = container;
    track->track_info.track_namespace_num = track_namespace_num;
    track->track_info.track_namespace_tuple =
    xqc_calloc(track_namespace_num, sizeof(xqc_moq_track_ns_field_t));
    if (track->track_info.track_namespace_tuple == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|track namespace tuple alloc fail|");
        xqc_moq_track_free_fields(track);
        xqc_free(track);
        return NULL;
    }
    for (uint64_t i = 0; i < track_namespace_num; i++) {
        track->track_info.track_namespace_tuple[i].len = track_namespace_tuple[i].len;
        if (track_namespace_tuple[i].len > 0 && track_namespace_tuple[i].data != NULL) {
            track->track_info.track_namespace_tuple[i].data =
                xqc_calloc(1, track_namespace_tuple[i].len + 1);
            if (track->track_info.track_namespace_tuple[i].data == NULL) {
                xqc_log(session->log, XQC_LOG_ERROR, "|track namespace tuple data alloc fail|");
                xqc_moq_track_free_fields(track);
                xqc_free(track);
                return NULL;
            }
            xqc_memcpy(track->track_info.track_namespace_tuple[i].data,
                       track_namespace_tuple[i].data, track_namespace_tuple[i].len);
        }
    }

    size_t track_name_len = strlen(track_name);
    if (track_name_len == 0 || track_name_len > XQC_MOQ_MAX_NAME_LEN) {
        xqc_log(session->log, XQC_LOG_ERROR, "|track name too long|");
        xqc_moq_track_free_fields(track);
        xqc_free(track);
        return NULL;
    }
    track->track_info.track_name = xqc_calloc(1, track_name_len + 1);
    if (track->track_info.track_name == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|track name alloc fail|");
        xqc_moq_track_free_fields(track);
        xqc_free(track);
        return NULL;
    }
    xqc_memcpy(track->track_info.track_name, track_name, track_name_len);

    track->track_alias = XQC_MOQ_INVALID_ID;
    track->subscribe_id = XQC_MOQ_INVALID_ID;
    track->streams_count = 0;
    track->cur_group_id = 0;
    track->cur_object_id = 0;
    track->cur_subgroup_id = 0;
    track->cur_subgroup_group_id = XQC_MOQ_INVALID_ID;
    track->raw_object = 0;

    if (role == XQC_MOQ_TRACK_FOR_PUB) {
        list = &session->track_list_for_pub;
    } else {
        list = &session->track_list_for_sub;
    }
    track->track_role = role;
    xqc_init_list_head(&track->list_member);
    xqc_list_add_tail(&track->list_member, list);

    if (role == XQC_MOQ_TRACK_FOR_PUB) {
        xqc_moq_session_discovery_on_track_added(session, track);
    }

    track->track_ops.on_create(track);

    xqc_log(session->log, XQC_LOG_INFO, "|track create success (tuple)|track_name:%s|track_role:%d|", track_name, role);

    return track;
}

void
xqc_moq_track_destroy(xqc_moq_track_t *track)
{
    if (track == NULL) {
        return;
    }

    xqc_moq_session_t *session = track->session;
    if (session != NULL && !session->is_destroying && track->track_role == XQC_MOQ_TRACK_FOR_PUB
        && !track->discovery_removed)
    {
        xqc_moq_session_discovery_on_track_removed(session, track);
        track->discovery_removed = 1;
    }

    if (track->active_stream_refcnt > 0) {
        track->destroy_pending = 1;
        return;
    }

    xqc_moq_track_finalize_destroy(track);
}

void
xqc_moq_track_free_fields(xqc_moq_track_t *track)
{
    if (track->track_info.track_namespace_tuple) {
        for (uint64_t i = 0; i < track->track_info.track_namespace_num; i++) {
            if (track->track_info.track_namespace_tuple[i].data) {
                xqc_free(track->track_info.track_namespace_tuple[i].data);
                track->track_info.track_namespace_tuple[i].data = NULL;
                track->track_info.track_namespace_tuple[i].len = 0;
            }
        }
        xqc_free(track->track_info.track_namespace_tuple);
        track->track_info.track_namespace_tuple = NULL;
        track->track_info.track_namespace_num = 0;
    }
    xqc_free(track->track_info.track_name);
    track->track_info.track_name = NULL;
    xqc_free(track->packaging);
    track->packaging = NULL;
    xqc_moq_track_free_params(&track->track_info.selection_params);
}

void
xqc_moq_track_stream_ref_inc(xqc_moq_track_t *track)
{
    if (track == NULL) {
        return;
    }
    track->active_stream_refcnt++;
}

void
xqc_moq_track_stream_ref_dec(xqc_moq_track_t *track)
{
    if (track == NULL) {
        return;
    }

    if (track->active_stream_refcnt > 0) {
        track->active_stream_refcnt--;
    }

    if (track->destroy_pending && track->active_stream_refcnt == 0) {
        xqc_moq_track_finalize_destroy(track);
    }
}

const char * xqc_moq_track_get_full_name(const xqc_moq_track_t *track)
{
    if (track == NULL) {
        return "null";
    }

    // NOTE: for logging only; do not use this representation for comparisons. 
    size_t off = 0;
    static char xqc_moq_track_full_name_buf[XQC_MOQ_TRACK_FULL_NAME_BUF_SIZE];
    xqc_moq_track_full_name_buf[0] = '\0';

    if (track->track_info.track_namespace_tuple != NULL && track->track_info.track_namespace_num > 0) {
        for (uint64_t i = 0; i < track->track_info.track_namespace_num && off < XQC_MOQ_TRACK_FULL_NAME_BUF_SIZE - 1; i++) {
            const xqc_moq_track_ns_field_t *field = &track->track_info.track_namespace_tuple[i];
            if (field->data != NULL && field->len > 0) {
                size_t copy_len = field->len;
                if (off + copy_len >= XQC_MOQ_TRACK_FULL_NAME_BUF_SIZE - 1) {
                    copy_len = XQC_MOQ_TRACK_FULL_NAME_BUF_SIZE - 1 - off;
                }
                xqc_memcpy(xqc_moq_track_full_name_buf + off, field->data, copy_len);
                off += copy_len;
            }
            if (i + 1 < track->track_info.track_namespace_num && off < XQC_MOQ_TRACK_FULL_NAME_BUF_SIZE - 1) {
                xqc_moq_track_full_name_buf[off++] = '/';
            }
        }
    }

    if (track->track_info.track_name != NULL && off < XQC_MOQ_TRACK_FULL_NAME_BUF_SIZE - 2) {
        xqc_moq_track_full_name_buf[off++] = '/';
        size_t name_len = strlen(track->track_info.track_name);
        if (off + name_len >= XQC_MOQ_TRACK_FULL_NAME_BUF_SIZE - 1) {
            name_len = XQC_MOQ_TRACK_FULL_NAME_BUF_SIZE - 1 - off;
        }
        xqc_memcpy(xqc_moq_track_full_name_buf + off, track->track_info.track_name, name_len);
        off += name_len;
    }

    xqc_moq_track_full_name_buf[off] = '\0';

    if (off == 0) {
        return "null";
    }
    return xqc_moq_track_full_name_buf;
}

void
xqc_moq_track_set_alias(xqc_moq_track_t *track, uint64_t track_alias)
{
    if (track->track_alias != track_alias) {
        xqc_log(track->session->log, XQC_LOG_DEBUG,
                "|track_alias_update|track:%s|old:%ui|new:%ui|",
                xqc_moq_track_get_full_name(track),
                track->track_alias, track_alias);
    }
    track->track_alias = track_alias;
}

void
xqc_moq_track_set_subscribe_id(xqc_moq_track_t *track, uint64_t subscribe_id)
{
    if (track->subscribe_id != subscribe_id) {
        xqc_log(track->session->log, XQC_LOG_DEBUG,
                "|track_subscribe_id_update|track:%s|old:%ui|new:%ui|",
                xqc_moq_track_get_full_name(track),
                track->subscribe_id, subscribe_id);
    }
    track->subscribe_id = subscribe_id;
}

void
xqc_moq_track_add_streams_count(xqc_moq_track_t *track)
{
    if (track == NULL) {
        return;
    }
    if (track->streams_count < (((uint64_t)1 << 62) - 1)) {
        track->streams_count++;
    }
}

uint64_t
xqc_moq_track_next_subgroup_id(xqc_moq_track_t *track, uint64_t group_id)
{
    if (track->cur_subgroup_group_id != group_id) {
        track->cur_subgroup_group_id = group_id;
        track->cur_subgroup_id = 0;
    }
    return track->cur_subgroup_id++;
}

void
xqc_moq_track_copy_params(xqc_moq_selection_params_t *dst, xqc_moq_selection_params_t *src)
{
    xqc_memcpy(dst, src, sizeof(xqc_moq_selection_params_t));
    size_t len;
    if (src->codec != NULL) {
        len = strlen(src->codec);
        dst->codec = xqc_calloc(1, len + 1);
        xqc_memcpy(dst->codec, src->codec, len);
    }
    if (src->mime_type != NULL) {
        len = strlen(src->mime_type);
        dst->mime_type = xqc_calloc(1, len + 1);
        xqc_memcpy(dst->mime_type, src->mime_type, len);
    }
    if (src->lang != NULL) {
        len = strlen(src->lang);
        dst->lang = xqc_calloc(1, len + 1);
        xqc_memcpy(dst->lang, src->lang, len);
    }
    if (src->channel_config != NULL) {
        len = strlen(src->channel_config);
        dst->channel_config = xqc_calloc(1, len + 1);
        xqc_memcpy(dst->channel_config, src->channel_config, len);
    }
}

void
xqc_moq_track_free_params(xqc_moq_selection_params_t *params)
{
    xqc_free(params->codec);
    params->codec = NULL;
    xqc_free(params->mime_type);
    params->mime_type = NULL;
    xqc_free(params->lang);
    params->lang = NULL;
    xqc_free(params->channel_config);
    params->channel_config = NULL;
}

void
xqc_moq_track_set_params(xqc_moq_track_t *track, xqc_moq_selection_params_t *params)
{
    xqc_moq_track_copy_params(&track->track_info.selection_params, params);
}

void
xqc_moq_track_set_raw_object(xqc_moq_track_t *track, xqc_int_t raw_object)
{
    if (track == NULL) {
        return;
    }
    track->raw_object = raw_object ? 1 : 0;
    if (track->raw_object) {
        track->container_format = XQC_MOQ_CONTAINER_NONE;
    }
}

void
xqc_moq_track_set_reuse_subgroup_stream(xqc_moq_track_t *track, xqc_int_t reuse)
{
    if (track == NULL) {
        return;
    }
    track->reuse_subgroup_stream = reuse ? 1 : 0;
}
