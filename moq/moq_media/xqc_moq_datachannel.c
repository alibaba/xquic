
#include "moq/moq_media/xqc_moq_datachannel.h"
#include "moq/moq_transport/xqc_moq_message_writer.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "src/transport/xqc_stream.h"

static void xqc_moq_datachannel_on_create(xqc_moq_track_t *track);
static void xqc_moq_datachannel_on_destroy(xqc_moq_track_t *track);
static void xqc_moq_datachannel_on_subscribe(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_msg_t *msg);
static void xqc_moq_datachannel_on_subscribe_ok(xqc_moq_session_t *session, xqc_moq_track_t *track,
    xqc_moq_subscribe_ok_msg_t *subscribe_ok);
static void xqc_moq_datachannel_on_subscribe_error(xqc_moq_session_t *session, xqc_moq_track_t *track,
    xqc_moq_subscribe_error_msg_t *subscribe_error);
static void xqc_moq_datachannel_on_object(xqc_moq_session_t *session, xqc_moq_track_t *track, xqc_moq_object_t *object);

const xqc_moq_track_ops_t xqc_moq_datachannel_track_ops = {
    .on_create           = xqc_moq_datachannel_on_create,
    .on_destroy          = xqc_moq_datachannel_on_destroy,
    .on_subscribe        = xqc_moq_datachannel_on_subscribe,
    .on_subscribe_update = NULL,
    .on_subscribe_ok     = xqc_moq_datachannel_on_subscribe_ok,
    .on_subscribe_error  = xqc_moq_datachannel_on_subscribe_error,
    .on_object           = xqc_moq_datachannel_on_object,
};

xqc_int_t
xqc_moq_write_datachannel_unordered(xqc_moq_session_t *session, uint8_t *msg, size_t msg_len)
{
    xqc_int_t ret = 0;
    xqc_moq_stream_t *stream;
    xqc_moq_object_stream_msg_t object;
    xqc_moq_track_t *track = session->datachannel.track_for_pub;

    stream = xqc_moq_stream_create_with_transport(session, XQC_STREAM_UNI);
    if (stream == NULL) {
        xqc_log(session->log, XQC_LOG_ERROR, "|create moq stream error|");
        return -XQC_ECREATE_STREAM;
    }
    stream->write_stream_fin = 1;

    object.subscribe_id = session->datachannel.peer_subscribe_id;
    object.track_alias = track->track_alias;
    object.send_order = 0; //TODO
    object.status = XQC_MOQ_OBJ_STATUS_NORMAL;
    object.payload = msg;
    object.payload_len = msg_len;
    object.group_id = track->cur_group_id;
    object.object_id = track->cur_object_id++;

    ret = xqc_moq_write_object_stream_msg(session, stream, &object);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|write_object_stream_msg error|ret:%d|", ret);
        return ret;
    }
    return XQC_OK;
}

xqc_int_t
xqc_moq_write_datachannel(xqc_moq_session_t *session, uint8_t *msg, size_t msg_len)
{
    xqc_int_t ret = 0;
    xqc_moq_stream_t *stream;
    xqc_stream_t *quic_stream;
    xqc_moq_stream_header_track_msg_t track_header;
    xqc_moq_track_stream_obj_msg_t obj;
    xqc_moq_track_t *track = session->datachannel.track_for_pub;

    if (session->datachannel.ready == 0) {
        return -XQC_ESTREAM_ST;
    }

    stream = session->datachannel.ordered_stream;
    if (stream == NULL) {
        stream = xqc_moq_stream_create_with_transport(session, XQC_STREAM_UNI);
        if (stream == NULL) {
            xqc_log(session->log, XQC_LOG_ERROR, "|create moq stream error|");
            return -XQC_ECREATE_STREAM;
        }
        
        quic_stream = stream->trans_ops.quic_stream(stream->trans_stream);
        xqc_stream_set_priority(quic_stream, XQC_STREAM_PRI_HIGH);
        
        session->datachannel.ordered_stream = stream;
    }

    track_header.subscribe_id = session->datachannel.peer_subscribe_id;
    track_header.track_alias = track->track_alias;
    track_header.send_order = 0; //TODO
    if (session->datachannel.msg_header_write == 0) {
        ret = xqc_moq_write_stream_header_track_msg(session, stream, &track_header);
        if (ret < 0) {
            xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_write_stream_header_track_msg error|ret:%d|", ret);
            return ret;
        }
        session->datachannel.msg_header_write = 1;
    }

    obj.track_header = track_header;
    obj.group_id = track->cur_group_id;
    obj.object_id = track->cur_object_id++;
    obj.payload_len = msg_len;
    obj.payload = msg;
    obj.status = 0;
    ret = xqc_moq_write_track_stream_obj_msg(session, stream, &obj);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_write_track_stream_obj_msg error|ret:%d|", ret);
        return ret;
    }

    xqc_log(session->log, XQC_LOG_INFO, "|write datachannel success|msg_len:%ui|", msg_len);

    return XQC_OK;
}

xqc_int_t
xqc_moq_send_datachannel_msg(xqc_moq_session_t *session, xqc_moq_track_t *track,
    uint8_t *msg, size_t msg_len)
{
    xqc_moq_subgroup_object_t subgroup;
    xqc_int_t ret = 0;
    uint64_t group_id;
    uint64_t object_id;
    uint64_t subgroup_id;

    if (session == NULL || track == NULL || msg == NULL || msg_len == 0) {
        return -XQC_EPARAM;
    }

    if (track->track_info.track_type != XQC_MOQ_TRACK_DATACHANNEL) {
        return -XQC_EPARAM;
    }

    if (track->subscribe_id == XQC_MOQ_INVALID_ID || track->track_alias == XQC_MOQ_INVALID_ID) {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|send_datachannel_msg invalid track|subscribe_id:%ui|track_alias:%ui|",
                track->subscribe_id, track->track_alias);
        return -XQC_ESTREAM_ST;
    }

    xqc_memzero(&subgroup, sizeof(subgroup));

    group_id = ++track->cur_group_id;
    track->cur_object_id = 0;
    subgroup_id = xqc_moq_track_next_subgroup_id(track, group_id);

    subgroup.subscribe_id = track->subscribe_id;
    subgroup.track_alias = track->track_alias;
    subgroup.group_id = group_id;
    subgroup.object_id = object_id;
    subgroup.subgroup_id = subgroup_id;
    subgroup.object_id_delta = 0;
    subgroup.subgroup_type = 0;
    subgroup.subgroup_priority = 0;
    subgroup.send_order = 0;
    subgroup.status = XQC_MOQ_OBJ_STATUS_NORMAL;
    subgroup.payload = msg;
    subgroup.payload_len = msg_len;

    ret = xqc_moq_send_subgroup(session, track, &subgroup);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_send_subgroup error|ret:%d|", ret);
        return ret;
    }

    xqc_log(session->log, XQC_LOG_INFO,
            "|send datachannel msg success (subgroup)|msg_len:%ui|group_id:%ui|object_id:%ui|subgroup_id:%ui|",
            msg_len, group_id, object_id, subgroup_id);

    return XQC_OK;
}

void
xqc_moq_datachannel_set_can_send(xqc_moq_session_t *session, xqc_moq_datachannel_t *dc)
{
    dc->can_send = 1;
    xqc_moq_datachannel_update_state(session, dc);
}

void
xqc_moq_datachannel_set_can_recv(xqc_moq_session_t *session, xqc_moq_datachannel_t *dc)
{
    dc->can_recv = 1;
    xqc_moq_datachannel_update_state(session, dc);
}

void
xqc_moq_datachannel_update_state(xqc_moq_session_t *session, xqc_moq_datachannel_t *dc)
{
    if (dc->can_send && dc->can_recv) {
        dc->ready = 1;
        xqc_log(session->log, XQC_LOG_INFO, "|on_datachannel|");
        xqc_moq_track_t *track = session->datachannel.track_for_sub;
        session->session_callbacks.on_datachannel(session->user_session, track,
            track ? &track->track_info : NULL);
    }
}

xqc_int_t
xqc_moq_subscribe_datachannel(xqc_moq_session_t *session)
{
    xqc_int_t ret;
    xqc_moq_track_t *track;
    track = xqc_moq_track_create(session, XQC_MOQ_DATACHANNEL_NAMESPACE, XQC_MOQ_DATACHANNEL_NAME,
                                 XQC_MOQ_TRACK_DATACHANNEL, NULL, XQC_MOQ_CONTAINER_NONE, XQC_MOQ_TRACK_FOR_PUB);
    session->datachannel.track_for_pub = track;
    track = xqc_moq_track_create(session, XQC_MOQ_DATACHANNEL_NAMESPACE, XQC_MOQ_DATACHANNEL_NAME,
                                 XQC_MOQ_TRACK_DATACHANNEL, NULL, XQC_MOQ_CONTAINER_NONE, XQC_MOQ_TRACK_FOR_SUB);
    session->datachannel.track_for_sub = track;
    ret = xqc_moq_subscribe_latest(session, XQC_MOQ_DATACHANNEL_NAMESPACE, XQC_MOQ_DATACHANNEL_NAME);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_subscribe_latest error|ret:%d|", ret);
        return ret;
    }
    session->datachannel.local_subscribe_id = ret;
    return ret;
}

/**
 * Datachannel track ops
 */

static void
xqc_moq_datachannel_on_create(xqc_moq_track_t *track)
{
    return;
}

static void
xqc_moq_datachannel_on_destroy(xqc_moq_track_t *track)
{
    return;
}

static void
xqc_moq_datachannel_on_subscribe(xqc_moq_session_t *session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_msg_t *msg)
{
    xqc_int_t ret;
    session->datachannel.peer_subscribe_id = subscribe_id;
    xqc_moq_datachannel_set_can_send(session, &session->datachannel);

    xqc_moq_subscribe_ok_msg_t subscribe_ok;
    memset(&subscribe_ok, 0, sizeof(subscribe_ok));
    subscribe_ok.subscribe_id = subscribe_id;
    subscribe_ok.track_alias = msg ? msg->track_alias : 0;
    subscribe_ok.expire_ms = 0;
    subscribe_ok.group_order = 0x1;
    subscribe_ok.content_exist = 1;
    subscribe_ok.largest_group_id = 0;
    subscribe_ok.largest_object_id = 0;
    ret = xqc_moq_write_subscribe_ok(session, &subscribe_ok);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|xqc_moq_write_subscribe_ok error|ret:%d|", ret);
        return;
    }
}

static void
xqc_moq_datachannel_on_subscribe_ok(xqc_moq_session_t *session, xqc_moq_track_t *track,
    xqc_moq_subscribe_ok_msg_t *subscribe_ok)
{
    xqc_moq_datachannel_set_can_recv(session, &session->datachannel);
}

static void
xqc_moq_datachannel_on_subscribe_error(xqc_moq_session_t *session, xqc_moq_track_t *track,
    xqc_moq_subscribe_error_msg_t *subscribe_error)
{
    return;
}

static void
xqc_moq_datachannel_on_object(xqc_moq_session_t *session, xqc_moq_track_t *track, xqc_moq_object_t *object)
{
    xqc_log(session->log, XQC_LOG_INFO, "|on_datachannel_msg|msg_len:%ui|", object->payload_len);
    xqc_log(session->log, XQC_LOG_INFO, "|on_datachannel_msg_detail|track:%s/%s|subscribe_id:%ui|",
            track && track->track_info.track_namespace ? track->track_info.track_namespace : "null",
            track && track->track_info.track_name ? track->track_info.track_name : "null",
            object->subscribe_id);
    session->session_callbacks.on_datachannel_msg(session->user_session, track,
        track ? &track->track_info : NULL, object->payload, object->payload_len);
}

