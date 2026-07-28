#include "moq/moq_transport/xqc_moq_track.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_message.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/xqc_moq_namespace.h"
#include "moq/moq_media/xqc_moq_catalog.h"
#include "moq/moq_media/xqc_moq_datachannel.h"
#include "moq/moq_media/xqc_moq_media_track.h"

void
xqc_moq_track_destroy(xqc_moq_track_t *track)
{
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &track->write_stream_list) {
        xqc_moq_stream_t *stream = xqc_list_entry(pos, xqc_moq_stream_t, list_member);
        xqc_list_del_init(&stream->list_member);
        if (stream->track == track) {
            stream->track = NULL;
        }
    }

    xqc_list_for_each_safe(pos, next, &track->recv_stream_list) {
        xqc_moq_stream_t *stream = xqc_list_entry(pos, xqc_moq_stream_t, recv_list_member);
        xqc_list_del_init(&stream->recv_list_member);
        if (stream->track == track) {
            stream->track = NULL;
        }
    }

    track->track_ops.on_destroy(track);

    xqc_moq_track_free_fields(track);
    xqc_free(track);
}

void
xqc_moq_track_free_fields(xqc_moq_track_t *track)
{
    xqc_moq_namespace_tuple_free(track->track_info.track_namespace_tuple, track->track_info.track_namespace_num);
    track->track_info.track_namespace_tuple = NULL;
    track->track_info.track_namespace_num = 0;
    xqc_free(track->track_info.track_namespace);
    track->track_info.track_namespace = NULL;
    xqc_free(track->track_info.track_name);
    track->track_info.track_name = NULL;
    xqc_free(track->packaging);
    track->packaging = NULL;
    xqc_moq_track_free_params(&track->track_info.selection_params);
}

void
xqc_moq_track_set_alias(xqc_moq_track_t *track, uint64_t track_alias)
{
    if (track->track_alias != track_alias) {
        char *ns = xqc_moq_namespace_tuple_join(track->track_info.track_namespace_tuple, track->track_info.track_namespace_num);
        xqc_log(track->session->log, XQC_LOG_DEBUG,
                "|track_alias_update|track:%s/%s|old:%ui|new:%ui|",
                ns ? ns : "null", track->track_info.track_name,
                track->track_alias, track_alias);
        xqc_free(ns);
    }
    track->track_alias = track_alias;
}

void
xqc_moq_track_set_subscribe_id(xqc_moq_track_t *track, uint64_t subscribe_id)
{
    if (track->subscribe_id != subscribe_id) {
        char *ns = xqc_moq_namespace_tuple_join(track->track_info.track_namespace_tuple, track->track_info.track_namespace_num);
        xqc_log(track->session->log, XQC_LOG_DEBUG,
                "|track_subscribe_id_update|track:%s/%s|old:%ui|new:%ui|",
                ns ? ns : "null", track->track_info.track_name,
                track->subscribe_id, subscribe_id);
        xqc_free(ns);
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
    if (dst == src) {
        return;
    }
    xqc_moq_track_free_params(dst);
    xqc_memcpy(dst, src, sizeof(xqc_moq_selection_params_t));
    dst->codec = NULL;
    dst->mime_type = NULL;
    dst->lang = NULL;
    dst->channel_config = NULL;
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

static xqc_bool_t
xqc_moq_group_filter_match(const xqc_moq_group_filter_t *filter, xqc_moq_stream_t *stream)
{
    switch (filter->type) {
    case XQC_MOQ_GROUP_FILTER_EXACT:
        return stream->group_id == filter->group_id;
    case XQC_MOQ_GROUP_FILTER_BEFORE:
        return stream->group_id < filter->group_id;
    default:
        return XQC_FALSE;
    }
}

xqc_int_t
xqc_moq_track_cancel_recv(xqc_moq_track_t *track, const xqc_moq_group_filter_t *filter)
{
    if (track == NULL || filter == NULL || track->track_role != XQC_MOQ_TRACK_FOR_SUB) {
        return -XQC_EPARAM;
    }

    if (filter->type != XQC_MOQ_GROUP_FILTER_EXACT
        && filter->type != XQC_MOQ_GROUP_FILTER_BEFORE)
    {
        return -XQC_EPARAM;
    }

    if (filter->type == XQC_MOQ_GROUP_FILTER_BEFORE) {
        track->drop_recv_group_id_before = xqc_max(track->drop_recv_group_id_before, filter->group_id);
        if (track->drop_recv_exact_group_id_valid
            && track->drop_recv_exact_group_id < track->drop_recv_group_id_before)
        {
            track->drop_recv_exact_group_id_valid = 0;
        }
    } else {
        track->drop_recv_exact_group_id = filter->group_id;
        track->drop_recv_exact_group_id_valid = 1;
    }

    xqc_int_t ret = XQC_OK;
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &track->recv_stream_list) {
        xqc_moq_stream_t *stream = xqc_list_entry(pos, xqc_moq_stream_t, recv_list_member);
        if (!xqc_moq_group_filter_match(filter, stream)) {
            continue;
        }

        xqc_list_del_init(&stream->recv_list_member);
        xqc_int_t stop_ret = xqc_moq_stream_stop_sending(stream, XQC_MOQ_DATA_STREAM_CANCELLED);
        if (stop_ret < 0 && ret == XQC_OK) {
            ret = stop_ret;
        }

        char *cancel_ns = xqc_moq_namespace_tuple_join(track->track_info.track_namespace_tuple, track->track_info.track_namespace_num);
        xqc_log(track->session->log, XQC_LOG_INFO,
                "|moq cancel recv stream|track:%s/%s|group_id:%ui|subgroup_id:%ui|ret:%d|",
                cancel_ns ? cancel_ns : "null",
                track->track_info.track_name ? track->track_info.track_name : "null",
                stream->group_id, stream->subgroup_id, stop_ret);
        xqc_free(cancel_ns);
    }

    return ret;
}

void
xqc_moq_track_on_write_stream(xqc_moq_track_t *track, xqc_moq_stream_t *stream,
    uint64_t group_id, uint64_t object_id, uint64_t seq_num)
{
    if (track == NULL || stream == NULL) {
        return;
    }

    xqc_moq_stream_on_track_write(stream, track, group_id, object_id, seq_num);
    if (xqc_list_empty(&stream->list_member)) {
        xqc_list_add_tail(&stream->list_member, &track->write_stream_list);
    }
}

xqc_bool_t
xqc_moq_track_should_drop_write_object(xqc_moq_track_t *track, uint64_t group_id,
    uint64_t object_id)
{
    if (track == NULL) {
        return XQC_FALSE;
    }

    if (group_id < track->drop_write_group_id_before) {
        return XQC_TRUE;
    }

    return XQC_FALSE;
}

void
xqc_moq_track_advance_write_location(xqc_moq_track_t *track,
    uint64_t *group_id, uint64_t *object_id)
{
    if (track == NULL || group_id == NULL || object_id == NULL) {
        return;
    }

    if (*group_id < track->drop_write_group_id_before) {
        *group_id = track->drop_write_group_id_before;
        *object_id = 0;
        track->cur_group_id = *group_id;
        track->cur_object_id = 1;
    }
}

xqc_int_t
xqc_moq_track_cancel_write(xqc_moq_track_t *track, const xqc_moq_group_filter_t *filter)
{
    if (track == NULL || filter == NULL || track->track_role != XQC_MOQ_TRACK_FOR_PUB) {
        return -XQC_EPARAM;
    }

    if (filter->type != XQC_MOQ_GROUP_FILTER_EXACT
        && filter->type != XQC_MOQ_GROUP_FILTER_BEFORE)
    {
        return -XQC_EPARAM;
    }

    if (filter->type == XQC_MOQ_GROUP_FILTER_BEFORE) {
        track->drop_write_group_id_before = xqc_max(track->drop_write_group_id_before, filter->group_id);
    }

    xqc_int_t ret = XQC_OK;
    xqc_list_head_t *pos, *next;
search_from_head:
    xqc_list_for_each_safe(pos, next, &track->write_stream_list) {
        xqc_moq_stream_t *stream = xqc_list_entry(pos, xqc_moq_stream_t, list_member);
        if (!xqc_moq_group_filter_match(filter, stream)) {
            continue;
        }

        xqc_list_del_init(&stream->list_member);
        if (track->subgroup_stream == stream) {
            track->subgroup_stream = NULL;
        }
        stream->cancel_write_close = 1;
        xqc_int_t close_ret = xqc_moq_stream_close(stream);
        if (close_ret < 0 && ret == XQC_OK) {
            ret = close_ret;
        }

        char *cancel_ns = xqc_moq_namespace_tuple_join(track->track_info.track_namespace_tuple, track->track_info.track_namespace_num);
        if (track->session && track->session->log) {
            xqc_log(track->session->log, XQC_LOG_INFO,
                    "|moq cancel write stream|track:%s/%s|group_id:%ui|subgroup_id:%ui|ret:%d|",
                    cancel_ns ? cancel_ns : "null",
                    track->track_info.track_name ? track->track_info.track_name : "null",
                    stream->group_id, stream->subgroup_id, close_ret);
        }
        xqc_free(cancel_ns);

        if (next->next == next) {
            goto search_from_head;
        }
    }

    return ret;
}

void
xqc_moq_track_on_recv_object(xqc_moq_track_t *track, xqc_moq_stream_t *stream,
    xqc_moq_object_t *object)
{
    if (track == NULL || stream == NULL || object == NULL) {
        return;
    }

    if (stream->track == NULL) {
        stream->track = track;
        stream->group_id = object->group_id;
        stream->object_id = object->object_id;
        stream->subgroup_id = object->subgroup_id;

    } else if (stream->track != track) {
        char *owner_ns = xqc_moq_namespace_tuple_join(stream->track->track_info.track_namespace_tuple, stream->track->track_info.track_namespace_num);
        char *cur_ns = xqc_moq_namespace_tuple_join(track->track_info.track_namespace_tuple, track->track_info.track_namespace_num);
        xqc_log(track->session->log, XQC_LOG_WARN,
                "|recv object on stream owned by another track|owner:%s/%s|current:%s/%s|group_id:%ui|subgroup_id:%ui|",
                owner_ns ? owner_ns : "null",
                stream->track->track_info.track_name ? stream->track->track_info.track_name : "null",
                cur_ns ? cur_ns : "null",
                track->track_info.track_name ? track->track_info.track_name : "null",
                object->group_id, object->subgroup_id);
        xqc_free(owner_ns);
        xqc_free(cur_ns);
        return;
    }

    if (xqc_list_empty(&stream->recv_list_member)) {
        xqc_list_add_tail(&stream->recv_list_member, &track->recv_stream_list);
    }
}

xqc_bool_t
xqc_moq_track_should_drop_recv_object(xqc_moq_track_t *track, xqc_moq_object_t *object)
{
    if (track == NULL || object == NULL) {
        return XQC_FALSE;
    }

    if (object->group_id < track->drop_recv_group_id_before) {
        return XQC_TRUE;
    }

    if (track->drop_recv_exact_group_id_valid
        && object->group_id == track->drop_recv_exact_group_id)
    {
        return XQC_TRUE;
    }

    return XQC_FALSE;
}

xqc_moq_track_t *
xqc_moq_track_create_with_ns_tuple(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *ns_tuple, uint64_t ns_num,
    char *track_name, xqc_moq_track_type_t track_type,
    xqc_moq_selection_params_t *params, xqc_moq_container_t container,
    xqc_moq_track_role_t role)
{
    xqc_moq_track_t *track;
    xqc_list_head_t *list;

    if (track_name == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|NULL track_name|");
        return NULL;
    }

    size_t track_name_len = strlen(track_name);
    if (xqc_moq_validate_full_track_name_for_write(session, ns_num, ns_tuple,
                                                    track_name, track_name_len) != XQC_OK)
    {
        return NULL;
    }

    track = xqc_moq_find_track_by_ns_tuple(session, ns_tuple, ns_num, track_name, role);
    if (track) {
        return track;
    }

    switch (track_type) {
        case XQC_MOQ_TRACK_VIDEO:
        case XQC_MOQ_TRACK_AUDIO:
            track = xqc_calloc(1, sizeof(xqc_moq_media_track_t));
            break;
        case XQC_MOQ_TRACK_DATACHANNEL:
            track = xqc_calloc(1, sizeof(xqc_moq_dc_track_t));
            break;
        case XQC_MOQ_TRACK_CATALOG:
            track = xqc_calloc(1, sizeof(xqc_moq_catalog_track_t));
            break;
        default:
            xqc_log(session->log, XQC_LOG_ERROR, "|unknown type|");
            return NULL;
    }
    if (track == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|track alloc failed|");
        return NULL;
    }

    switch (track_type) {
        case XQC_MOQ_TRACK_VIDEO:
        case XQC_MOQ_TRACK_AUDIO:
            track->track_ops = xqc_moq_media_track_ops;
            break;
        case XQC_MOQ_TRACK_DATACHANNEL:
            track->track_ops = xqc_moq_datachannel_track_ops;
            break;
        case XQC_MOQ_TRACK_CATALOG:
            track->track_ops = xqc_moq_catalog_track_ops;
            break;
        default:
            break;
    }

    track->track_info.track_namespace_tuple = xqc_moq_namespace_tuple_copy(ns_tuple, ns_num);
    if (track->track_info.track_namespace_tuple == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|namespace tuple copy failed|");
        xqc_free(track);
        return NULL;
    }

    track->track_info.track_namespace = xqc_moq_namespace_tuple_join(ns_tuple, ns_num);
    if (track->track_info.track_namespace == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|namespace join failed|");
        xqc_moq_namespace_tuple_free(track->track_info.track_namespace_tuple, ns_num);
        xqc_free(track);
        return NULL;
    }

    track->track_info.track_name = xqc_calloc(1, track_name_len + 1);
    if (track->track_info.track_name == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|track name alloc failed|");
        xqc_free(track->track_info.track_namespace);
        xqc_moq_namespace_tuple_free(track->track_info.track_namespace_tuple, ns_num);
        xqc_free(track);
        return NULL;
    }
    xqc_memcpy(track->track_info.track_name, track_name, track_name_len);

    if (params) {
        xqc_moq_track_copy_params(&track->track_info.selection_params, params);
    }
    track->session = session;
    track->track_info.track_type = track_type;
    track->container_format = container;
    track->track_info.track_namespace_num = ns_num;
    track->track_alias = XQC_MOQ_INVALID_ID;
    track->subscribe_id = XQC_MOQ_INVALID_ID;
    track->cur_subgroup_group_id = XQC_MOQ_INVALID_ID;

    if (role == XQC_MOQ_TRACK_FOR_PUB) {
        list = &session->track_list_for_pub;
    } else {
        list = &session->track_list_for_sub;
    }
    track->track_role = role;
    xqc_init_list_head(&track->list_member);
    xqc_init_list_head(&track->write_stream_list);
    xqc_init_list_head(&track->recv_stream_list);
    xqc_list_add_tail(&track->list_member, list);

    track->track_ops.on_create(track);

    xqc_log(session->log, XQC_LOG_INFO, "|track create success|track_name:%s|track_role:%d|", track_name, role);

    return track;
}

xqc_moq_track_t *
xqc_moq_track_create(xqc_moq_session_t *session, char *track_namespace, char *track_name,
    xqc_moq_track_type_t track_type, xqc_moq_selection_params_t *params,
    xqc_moq_container_t container, xqc_moq_track_role_t role)
{
    if (track_namespace == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|NULL ptr|");
        return NULL;
    }

    xqc_moq_track_ns_field_t field;
    field.data = (unsigned char *)track_namespace;
    field.len = strlen(track_namespace);
    if (field.len == 0 || field.len > XQC_MOQ_MAX_NAME_LEN) {
        xqc_log(session->log, XQC_LOG_ERROR, "|namespace or name too long|");
        return NULL;
    }

    return xqc_moq_track_create_with_ns_tuple(session, &field, 1, track_name,
                                               track_type, params, container, role);
}
