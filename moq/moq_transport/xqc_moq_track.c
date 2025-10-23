#include "moq/moq_transport/xqc_moq_track.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_message.h"
#include "moq/moq_media/xqc_moq_catalog.h"
#include "moq/moq_media/xqc_moq_datachannel.h"
#include "moq/moq_media/xqc_moq_media_track.h"
#include "moq/moq_media/xqc_moq_container.h"

xqc_moq_track_t *
xqc_moq_track_create(xqc_moq_session_t *session, char *track_namespace, char *track_name,
    xqc_moq_track_type_t track_type, xqc_moq_selection_params_t *params, xqc_moq_container_t container, xqc_moq_track_role_t role)
{
    xqc_moq_track_t *track;
    xqc_list_head_t *list;

    if (track_namespace == NULL || track_name == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|NULL ptr|");
        return NULL;
    }

    size_t track_namespace_len = strlen(track_namespace);
    size_t track_name_len = strlen(track_name);
    if (track_namespace_len > XQC_MOQ_MAX_NAME_LEN || track_name_len > XQC_MOQ_MAX_NAME_LEN
        || track_namespace_len == 0 || track_name_len == 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|namespace or name too long|");
        return NULL;
    }

    track = xqc_moq_find_track_by_name(session, track_namespace, track_name, role);
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
    track->track_info.track_namespace = xqc_calloc(1, track_namespace_len + 1);
    xqc_memcpy(track->track_info.track_namespace, track_namespace, track_namespace_len);
    track->track_info.track_name = xqc_calloc(1, track_name_len + 1);
    xqc_memcpy(track->track_info.track_name, track_name, track_name_len);
    track->track_alias = -1;
    track->subscribe_id = -1;

    if (role == XQC_MOQ_TRACK_FOR_PUB) {
        list = &session->track_list_for_pub;
    } else {
        list = &session->track_list_for_sub;
    }
    track->track_role = role;
    xqc_init_list_head(&track->list_member);
    xqc_list_add_tail(&track->list_member, list);

    track->track_ops.on_create(track);

    xqc_log(session->log, XQC_LOG_INFO, "|track create success|track_name:%s|track_role:%d|", track_name, role);

    return track;
}

void
xqc_moq_track_destroy(xqc_moq_track_t *track)
{
    track->track_ops.on_destroy(track);

    xqc_moq_track_free_fields(track);
    xqc_free(track);
}

void
xqc_moq_track_free_fields(xqc_moq_track_t *track)
{
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
    track->track_alias = track_alias;
}

void
xqc_moq_track_set_subscribe_id(xqc_moq_track_t *track, uint64_t subscribe_id)
{
    track->subscribe_id = subscribe_id;
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