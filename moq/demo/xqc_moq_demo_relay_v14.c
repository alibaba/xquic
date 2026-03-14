#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <memory.h>
#include <string.h>
#include <stdlib.h>
#include <event2/event.h>
#include <inttypes.h>
#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <arpa/inet.h>
#
#include "tests/platform.h"
#include "xqc_moq_demo_comm.h"
#
#ifndef XQC_SYS_WINDOWS
#include <unistd.h>
#include <getopt.h>
#else
#include "getopt.h"
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "crypt32")
#endif
#
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_namespace.h"
#include "moq/moq_transport/xqc_moq_message.h"

#define DEBUG printf("%s:%d (%s)\n", __FILE__, __LINE__, __FUNCTION__);

#define TEST_ADDR "127.0.0.1"
#define TEST_PORT 4433

extern long xqc_random(void);
extern xqc_usec_t xqc_now();

static xqc_app_ctx_t g_app_ctx;
static struct event_base *g_event_base;

static int g_ipv6 = 0;
static int g_enable_client_setup_v14 = 1;

static int g_relay_port = TEST_PORT;
static char g_log_level = 'd';

typedef struct xqc_moq_relay_downstream_s {
    xqc_list_head_t          list_member;
    xqc_moq_session_t        *session;
    xqc_moq_track_t          *track;
    uint64_t                 subscribe_id;
    uint8_t                  publish_ok_received;
} xqc_moq_relay_downstream_t;

typedef struct xqc_moq_relay_forwarding_s {
    xqc_list_head_t              list_member;
    xqc_moq_session_t            *upstream_session;
    uint64_t                     upstream_subscribe_id;
    xqc_moq_track_t              *upstream_track;
    xqc_moq_track_type_t         track_type;
    uint64_t                     track_namespace_num;
    xqc_moq_track_ns_field_t     *track_namespace_tuple;
    char                         *track_name;
    xqc_list_head_t              downstream_list;
} xqc_moq_relay_forwarding_t;

typedef struct xqc_moq_relay_conn_s {
    user_conn_t              base; /* must be first: used by demo_comm write_socket helpers */
    xqc_list_head_t          list_member;
    xqc_moq_user_session_t   *user_session;
    xqc_moq_session_t        *session;
    xqc_connection_t         *conn;
    xqc_cid_t                cid;
} xqc_moq_relay_conn_t;

typedef struct xqc_moq_relay_pub_namespace_s {
    xqc_list_head_t              list_member;
    xqc_moq_session_t            *session;
    uint64_t                     track_namespace_num;
    xqc_moq_track_ns_field_t     *track_namespace_tuple;
} xqc_moq_relay_pub_namespace_t;

static xqc_list_head_t g_relay_conn_list;
static xqc_list_head_t g_relay_forwarding_list;
static xqc_list_head_t g_relay_pub_namespace_list;

static xqc_int_t
xqc_moq_relay_forwarding_has_downstream(xqc_moq_relay_forwarding_t *forwarding, xqc_moq_session_t *downstream_session)
{
    if (forwarding == NULL || downstream_session == NULL) {
        return 0;
    }

    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &forwarding->downstream_list) {
        xqc_moq_relay_downstream_t *downstream = xqc_list_entry(pos, xqc_moq_relay_downstream_t, list_member);
        if (downstream->session == downstream_session) {
            return 1;
        }
    }
    return 0;
}

static xqc_int_t
xqc_moq_relay_peer_wants_namespace(xqc_moq_session_t *session,
    const xqc_moq_track_ns_field_t *track_namespace_tuple, uint64_t track_namespace_num)
{
    if (session == NULL || track_namespace_tuple == NULL || track_namespace_num == 0) {
        return 0;
    }

    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &session->peer_subscribe_namespace_list) {
        xqc_moq_namespace_prefix_t *prefix = xqc_list_entry(pos, xqc_moq_namespace_prefix_t, list_member);
        if (prefix->prefix_tuple == NULL || prefix->prefix_num == 0) {
            continue;
        }
        if (xqc_moq_namespace_tuple_is_prefix(prefix->prefix_tuple, prefix->prefix_num,
                track_namespace_tuple, track_namespace_num)) {
            return 1;
        }
    }
    return 0;
}

static xqc_int_t
xqc_moq_relay_session_is_active(xqc_moq_session_t *session)
{
    if (session == NULL) {
        return 0;
    }

    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &g_relay_conn_list) {
        xqc_moq_relay_conn_t *conn_ctx = xqc_list_entry(pos, xqc_moq_relay_conn_t, list_member);
        if (conn_ctx->session == session) {
            return conn_ctx->base.closing_notified ? 0 : 1;
        }
    }
    return 0;
}

static void
xqc_moq_relay_forwarding_cleanup(xqc_moq_relay_forwarding_t *forwarding, xqc_int_t destroy_downstream_tracks)
{
    if (forwarding == NULL) {
        return;
    }

    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &forwarding->downstream_list) {
        xqc_moq_relay_downstream_t *downstream = xqc_list_entry(pos, xqc_moq_relay_downstream_t, list_member);
        xqc_list_del(&downstream->list_member);

        if (destroy_downstream_tracks
            && downstream->track != NULL
            && downstream->session != NULL
            && xqc_moq_relay_session_is_active(downstream->session))
        {
            if (downstream->track->list_member.next != XQC_LIST_POISON1
                && downstream->track->list_member.prev != XQC_LIST_POISON2)
            {
                xqc_list_del(&downstream->track->list_member);
            }
            xqc_moq_track_destroy(downstream->track);
            downstream->track = NULL;
        }
        xqc_free(downstream);
    }

    if (forwarding->track_namespace_tuple != NULL) {
        xqc_moq_namespace_tuple_free(forwarding->track_namespace_tuple, forwarding->track_namespace_num);
        forwarding->track_namespace_tuple = NULL;
        forwarding->track_namespace_num = 0;
    }

    if (forwarding->track_name != NULL) {
        xqc_free(forwarding->track_name);
        forwarding->track_name = NULL;
    }

    xqc_free(forwarding);
}

static xqc_moq_relay_forwarding_t *
xqc_moq_relay_find_forwarding(xqc_moq_session_t *upstream_session, uint64_t upstream_subscribe_id)
{
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &g_relay_forwarding_list) {
        xqc_moq_relay_forwarding_t *forwarding = xqc_list_entry(pos, xqc_moq_relay_forwarding_t, list_member);
        if (forwarding->upstream_session == upstream_session
            && forwarding->upstream_subscribe_id == upstream_subscribe_id) {
            return forwarding;
        }
    }
    return NULL;
}

static void
xqc_moq_relay_on_publish_ok(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_publish_ok_msg_t *publish_ok)
{
    (void)user_session;
    if (publish_ok == NULL) {
        return;
    }

    xqc_list_head_t *pos_fwd;
    xqc_list_for_each(pos_fwd, &g_relay_forwarding_list) {
        xqc_moq_relay_forwarding_t *forwarding = xqc_list_entry(pos_fwd, xqc_moq_relay_forwarding_t, list_member);
        xqc_list_head_t *pos_ds;
        xqc_list_for_each(pos_ds, &forwarding->downstream_list) {
            xqc_moq_relay_downstream_t *downstream = xqc_list_entry(pos_ds, xqc_moq_relay_downstream_t, list_member);
            if (downstream->session == user_session->session && downstream->subscribe_id == publish_ok->subscribe_id) {
                downstream->publish_ok_received = 1;
                printf("relay downstream publish_ok: subscribe_id:%"PRIu64" track_ptr:%p\n",
                       publish_ok->subscribe_id, (void *)track);
                return;
            }
        }
    }
}

static void
xqc_moq_relay_attach_forwarding_to_subscriber(xqc_moq_relay_forwarding_t *forwarding,
    xqc_moq_relay_conn_t *subscriber_conn_ctx)
{
    if (forwarding == NULL || subscriber_conn_ctx == NULL || subscriber_conn_ctx->session == NULL) {
        return;
    }

    xqc_moq_session_t *subscriber_session = subscriber_conn_ctx->session;
    if (!xqc_moq_relay_session_is_active(subscriber_session)) {
        return;
    }
    if ((subscriber_session->peer_role & XQC_MOQ_SUBSCRIBER) == 0) {
        return;
    }
    if (subscriber_session == forwarding->upstream_session) {
        return;
    }
    if (!xqc_moq_relay_peer_wants_namespace(subscriber_session,
            forwarding->track_namespace_tuple, forwarding->track_namespace_num)) {
        return;
    }
    if (xqc_moq_relay_forwarding_has_downstream(forwarding, subscriber_session)) {
        return;
    }

    xqc_moq_track_t *down_track = xqc_moq_find_track_by_track_namespace_tuple(subscriber_session,
        forwarding->track_namespace_tuple, forwarding->track_namespace_num,
        forwarding->track_name, XQC_MOQ_TRACK_FOR_PUB);

    if (down_track == NULL) {
        xqc_moq_container_t container = XQC_MOQ_CONTAINER_LOC;
        if (forwarding->track_type == XQC_MOQ_TRACK_DATACHANNEL) {
            container = XQC_MOQ_CONTAINER_NONE;
        }
        down_track = xqc_moq_track_create_with_namespace_tuple(subscriber_session,
            forwarding->track_namespace_num, forwarding->track_namespace_tuple,
            forwarding->track_name, forwarding->track_type,
            NULL, container, XQC_MOQ_TRACK_FOR_PUB);
    }

    if (down_track == NULL) {
        return;
    }

    xqc_moq_relay_downstream_t *downstream = xqc_calloc(1, sizeof(*downstream));
    if (downstream == NULL) {
        return;
    }
    xqc_init_list_head(&downstream->list_member);
    downstream->session = subscriber_session;
    downstream->track = down_track;
    downstream->subscribe_id = down_track->subscribe_id;
    downstream->publish_ok_received = 0;
    xqc_list_add_tail(&downstream->list_member, &forwarding->downstream_list);

    printf("relay history forward publish: upstream_subscribe_id:%"PRIu64" -> downstream_subscribe_id:%"PRIu64" track:%s/%s\n",
           forwarding->upstream_subscribe_id,
           downstream->subscribe_id,
           xqc_demo_namespace_tuple_to_str(forwarding->track_namespace_tuple, forwarding->track_namespace_num),
           forwarding->track_name ? forwarding->track_name : "null");
}

static void
xqc_moq_relay_forward_publish_to_downstreams(xqc_moq_session_t *upstream_session,
    xqc_moq_track_t *upstream_track, xqc_moq_publish_msg_t *publish_msg)
{
    if (upstream_session == NULL || upstream_track == NULL || publish_msg == NULL) {
        return;
    }

    xqc_moq_relay_forwarding_t *forwarding =
        xqc_moq_relay_find_forwarding(upstream_session, publish_msg->subscribe_id);
    if (forwarding == NULL) {
        forwarding = xqc_calloc(1, sizeof(*forwarding));
        if (forwarding == NULL) {
            return;
        }
        xqc_init_list_head(&forwarding->list_member);
        xqc_init_list_head(&forwarding->downstream_list);
        forwarding->upstream_session = upstream_session;
        forwarding->upstream_subscribe_id = publish_msg->subscribe_id;
        forwarding->upstream_track = upstream_track;
        forwarding->track_type = upstream_track->track_info.track_type;
        forwarding->track_namespace_num = publish_msg->track_namespace_num;
        forwarding->track_namespace_tuple = xqc_moq_namespace_tuple_copy(publish_msg->track_namespace_tuple,
                                                                  publish_msg->track_namespace_num);
        if (publish_msg->track_name != NULL) {
            size_t name_len = strlen(publish_msg->track_name);
            forwarding->track_name = xqc_calloc(1, name_len + 1);
            if (forwarding->track_name != NULL) {
                xqc_memcpy(forwarding->track_name, publish_msg->track_name, name_len);
            }
        }
        xqc_list_add_tail(&forwarding->list_member, &g_relay_forwarding_list);
    }

    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &g_relay_conn_list) {
        xqc_moq_relay_conn_t *conn_ctx = xqc_list_entry(pos, xqc_moq_relay_conn_t, list_member);
        if (conn_ctx->session == NULL || conn_ctx->session == upstream_session) {
            continue;
        }
        if ((conn_ctx->session->peer_role & XQC_MOQ_SUBSCRIBER) == 0) {
            continue;
        }
        if (!xqc_moq_relay_peer_wants_namespace(conn_ctx->session,
                publish_msg->track_namespace_tuple, publish_msg->track_namespace_num)) {
            continue;
        }

        xqc_moq_track_t *down_track = xqc_moq_find_track_by_track_namespace_tuple(conn_ctx->session,
            publish_msg->track_namespace_tuple, publish_msg->track_namespace_num,
            publish_msg->track_name, XQC_MOQ_TRACK_FOR_PUB);

        if (down_track == NULL) {
            xqc_moq_container_t container = XQC_MOQ_CONTAINER_LOC;
            if (forwarding->track_type == XQC_MOQ_TRACK_DATACHANNEL) {
                container = XQC_MOQ_CONTAINER_NONE;
            }
            down_track = xqc_moq_track_create_with_namespace_tuple(conn_ctx->session,
                publish_msg->track_namespace_num, publish_msg->track_namespace_tuple,
                publish_msg->track_name, forwarding->track_type,
                &upstream_track->track_info.selection_params, container, XQC_MOQ_TRACK_FOR_PUB);
        }

        if (down_track == NULL) {
            continue;
        }

        if (xqc_moq_relay_forwarding_has_downstream(forwarding, conn_ctx->session)) {
            continue;
        }

        xqc_moq_relay_downstream_t *downstream = xqc_calloc(1, sizeof(*downstream));
        if (downstream == NULL) {
            continue;
        }
        xqc_init_list_head(&downstream->list_member);
        downstream->session = conn_ctx->session;
        downstream->track = down_track;
        downstream->subscribe_id = down_track->subscribe_id;
        downstream->publish_ok_received = 0;
        xqc_list_add_tail(&downstream->list_member, &forwarding->downstream_list);

        printf("relay forward publish: upstream_subscribe_id:%"PRIu64" -> downstream_subscribe_id:%"PRIu64" track:%s/%s\n",
               forwarding->upstream_subscribe_id, downstream->subscribe_id,
               xqc_demo_namespace_tuple_to_str(publish_msg->track_namespace_tuple, publish_msg->track_namespace_num),
               publish_msg->track_name ? publish_msg->track_name : "null");
    }
}

static void
xqc_moq_relay_on_publish(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_publish_msg_t *publish_msg)
{
    if (user_session == NULL || user_session->session == NULL || track == NULL || publish_msg == NULL) {
        return;
    }
    xqc_moq_session_t *session = user_session->session;

    printf("relay on_publish: subscribe_id:%"PRIu64" track:%s/%s\n",
           publish_msg->subscribe_id,
           xqc_demo_namespace_tuple_to_str(publish_msg->track_namespace_tuple, publish_msg->track_namespace_num),
           publish_msg->track_name ? publish_msg->track_name : "null");

    xqc_moq_publish_ok_msg_t publish_ok;
    memset(&publish_ok, 0, sizeof(publish_ok));
    publish_ok.subscribe_id = publish_msg->subscribe_id;
    publish_ok.forward = 1;
    publish_ok.subscriber_priority = 0;
    publish_ok.group_order = publish_msg->group_order;
    publish_ok.filter_type = XQC_MOQ_FILTER_LAST_GROUP;
    publish_ok.start_group_id = 0;
    publish_ok.start_object_id = 0;
    publish_ok.end_group_id = 0;
    publish_ok.params_num = 0;
    publish_ok.params = NULL;
    if (xqc_moq_write_publish_ok(session, &publish_ok) < 0) {
        printf("relay xqc_moq_write_publish_ok error\n");
        return;
    }

    xqc_moq_relay_forward_publish_to_downstreams(session, track, publish_msg);
}

static void
xqc_moq_relay_on_publish_done(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_publish_done_msg_t *publish_done)
{
    (void)track;
    if (user_session == NULL || user_session->session == NULL || publish_done == NULL) {
        return;
    }

    xqc_moq_session_t *upstream_session = user_session->session;
    xqc_moq_relay_forwarding_t *forwarding =
        xqc_moq_relay_find_forwarding(upstream_session, publish_done->subscribe_id);
    if (forwarding == NULL) {
        return;
    }

    printf("relay on_publish_done: subscribe_id:%"PRIu64" status:%"PRIu64"\n",
           publish_done->subscribe_id, publish_done->status_code);

    xqc_list_del(&forwarding->list_member);
    xqc_moq_relay_forwarding_cleanup(forwarding, 1);
}

static void
xqc_moq_relay_on_video_frame(xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
    xqc_moq_video_frame_t *video_frame)
{
    if (user_session == NULL || user_session->session == NULL || video_frame == NULL) {
        return;
    }
    xqc_moq_session_t *session = user_session->session;
    xqc_moq_relay_forwarding_t *fwd = xqc_moq_relay_find_forwarding(session, subscribe_id);
    if (fwd == NULL) {
        return;
    }

    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &fwd->downstream_list) {
        xqc_moq_relay_downstream_t *downstream = xqc_list_entry(pos, xqc_moq_relay_downstream_t, list_member);
        if (!downstream->publish_ok_received || downstream->track == NULL
            || downstream->subscribe_id == XQC_MOQ_INVALID_ID) {
            continue;
        }
        if (!xqc_moq_relay_session_is_active(downstream->session)) {
            continue;
        }
        (void)xqc_moq_write_video_frame(downstream->session, downstream->subscribe_id, downstream->track, video_frame);
    }
}

static void
xqc_moq_relay_on_audio_frame(xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
    xqc_moq_audio_frame_t *audio_frame)
{
    if (user_session == NULL || user_session->session == NULL || audio_frame == NULL) {
        return;
    }
    xqc_moq_session_t *session = user_session->session;
    xqc_moq_relay_forwarding_t *fwd = xqc_moq_relay_find_forwarding(session, subscribe_id);
    if (fwd == NULL) {
        return;
    }

    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &fwd->downstream_list) {
        xqc_moq_relay_downstream_t *downstream = xqc_list_entry(pos, xqc_moq_relay_downstream_t, list_member);
        if (!downstream->publish_ok_received || downstream->track == NULL
            || downstream->subscribe_id == XQC_MOQ_INVALID_ID) {
            continue;
        }
        if (!xqc_moq_relay_session_is_active(downstream->session)) {
            continue;
        }
        (void)xqc_moq_write_audio_frame(downstream->session, downstream->subscribe_id, downstream->track, audio_frame);
    }
}

static void
xqc_moq_relay_detach_session_from_forwardings(xqc_moq_session_t *session)
{
    xqc_list_head_t *pos_forwarding, *next_forwarding;
    xqc_list_for_each_safe(pos_forwarding, next_forwarding, &g_relay_forwarding_list) {
        xqc_moq_relay_forwarding_t *forwarding =
            xqc_list_entry(pos_forwarding, xqc_moq_relay_forwarding_t, list_member);

        if (forwarding->upstream_session == session) {
            xqc_list_del(&forwarding->list_member);
            xqc_moq_relay_forwarding_cleanup(forwarding, 1);
            continue;
        }

        xqc_list_head_t *pos_downstream, *next_downstream;
        xqc_list_for_each_safe(pos_downstream, next_downstream, &forwarding->downstream_list) {
            xqc_moq_relay_downstream_t *downstream =
                xqc_list_entry(pos_downstream, xqc_moq_relay_downstream_t, list_member);
            if (downstream->session == session) {
                xqc_list_del(&downstream->list_member);
                xqc_free(downstream);
            }
        }
    }
}

static xqc_moq_relay_pub_namespace_t *
xqc_moq_relay_find_pub_namespace_for_track(
    const xqc_moq_track_ns_field_t *track_namespace_tuple, uint64_t track_namespace_num,
    xqc_moq_session_t *exclude_session)
{
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &g_relay_pub_namespace_list) {
        xqc_moq_relay_pub_namespace_t *pub_ns =
            xqc_list_entry(pos, xqc_moq_relay_pub_namespace_t, list_member);
        if (pub_ns->session == exclude_session) {
            continue;
        }
        if (!xqc_moq_relay_session_is_active(pub_ns->session)) {
            continue;
        }
        if (xqc_moq_namespace_tuple_is_prefix(pub_ns->track_namespace_tuple, pub_ns->track_namespace_num,
                track_namespace_tuple, track_namespace_num))
        {
            return pub_ns;
        }
    }
    return NULL;
}

static void
xqc_moq_relay_detach_pub_namespaces(xqc_moq_session_t *session)
{
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &g_relay_pub_namespace_list) {
        xqc_moq_relay_pub_namespace_t *pub_ns =
            xqc_list_entry(pos, xqc_moq_relay_pub_namespace_t, list_member);
        if (pub_ns->session == session) {
            xqc_list_del(&pub_ns->list_member);
            if (pub_ns->track_namespace_tuple != NULL) {
                xqc_moq_namespace_tuple_free(pub_ns->track_namespace_tuple, pub_ns->track_namespace_num);
            }
            xqc_free(pub_ns);
        }
    }
}

static void
xqc_moq_relay_on_publish_namespace(xqc_moq_user_session_t *user_session,
    xqc_moq_publish_namespace_msg_t *msg)
{
    if (user_session == NULL || user_session->session == NULL || msg == NULL) {
        return;
    }

    xqc_moq_session_t *session = user_session->session;

    xqc_moq_relay_pub_namespace_t *pub_ns = xqc_calloc(1, sizeof(*pub_ns));
    if (pub_ns == NULL) {
        return;
    }
    xqc_init_list_head(&pub_ns->list_member);
    pub_ns->session = session;
    pub_ns->track_namespace_num = msg->track_namespace_num;
    pub_ns->track_namespace_tuple = xqc_moq_namespace_tuple_copy(
        msg->track_namespace_tuple, msg->track_namespace_num);
    if (pub_ns->track_namespace_tuple == NULL) {
        xqc_free(pub_ns);
        return;
    }
    xqc_list_add_tail(&pub_ns->list_member, &g_relay_pub_namespace_list);

    printf("relay on_publish_namespace: session:%p namespace:%s\n",
           (void *)session,
           xqc_demo_namespace_tuple_to_str(msg->track_namespace_tuple, msg->track_namespace_num));

    xqc_moq_publish_namespace_ok_msg_t ok;
    memset(&ok, 0, sizeof(ok));
    ok.request_id = msg->request_id;
    xqc_int_t ret = xqc_moq_write_publish_namespace_ok(session, &ok);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|write_publish_namespace_ok error|ret:%d|", ret);
        xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on publish namespace");
    }
}

static void
xqc_moq_relay_on_subscribe_namespace(xqc_moq_user_session_t *user_session, xqc_moq_subscribe_namespace_msg_t *msg)
{
    if (user_session == NULL || user_session->session == NULL || msg == NULL) {
        return;
    }

    xqc_moq_session_t *session = user_session->session;

    if (msg->track_namespace_tuple == NULL
        || msg->track_namespace_num == 0
        || msg->track_namespace_num > XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS)
    {
        xqc_log(session->log, XQC_LOG_ERROR,
                "|subscribe_namespace invalid prefix|request_id:%ui|prefix_num:%ui|",
                msg->request_id, msg->track_namespace_num);
        xqc_moq_session_error(session, MOQ_PROTOCOL_VIOLATION, "subscribe namespace invalid prefix");
        return;
    }

    if (xqc_moq_session_namespace_prefix_overlaps(session, msg->track_namespace_tuple, msg->track_namespace_num)) {
        xqc_moq_subscribe_namespace_error_msg_t err;
        memset(&err, 0, sizeof(err));
        err.request_id = msg->request_id;
        err.error_code = XQC_MOQ_SUBSCRIBE_NAMESPACE_ERR_PREFIX_OVERLAP;
        err.reason_phrase = "namespace prefix overlap";
        xqc_int_t ret = xqc_moq_write_subscribe_namespace_error(session, &err);
        if (ret < 0) {
            xqc_log(session->log, XQC_LOG_ERROR, "|write_subscribe_namespace_error error|ret:%d|", ret);
            xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on subscribe namespace");
        }
        return;
    }

    xqc_int_t ret = xqc_moq_session_add_namespace_prefix(session, msg->track_namespace_tuple, msg->track_namespace_num);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|add namespace prefix failed|ret:%d|", ret);
        xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on subscribe namespace");
        return;
    }

    xqc_moq_subscribe_namespace_ok_msg_t ok;
    memset(&ok, 0, sizeof(ok));
    ok.request_id = msg->request_id;
    ret = xqc_moq_write_subscribe_namespace_ok(session, &ok);
    if (ret < 0) {
        xqc_log(session->log, XQC_LOG_ERROR, "|write_subscribe_namespace_ok error|ret:%d|", ret);
        xqc_moq_session_error(session, MOQ_INTERNAL_ERROR, "on subscribe namespace");
        return;
    }

    xqc_moq_relay_conn_t *subscriber_conn_ctx = (xqc_moq_relay_conn_t *)user_session->data;
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, &g_relay_forwarding_list) {
        xqc_moq_relay_forwarding_t *forwarding = xqc_list_entry(pos, xqc_moq_relay_forwarding_t, list_member);
        xqc_moq_relay_attach_forwarding_to_subscriber(forwarding, subscriber_conn_ctx);
    }
}

static xqc_int_t
xqc_server_conn_closing_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
    xqc_int_t err_code, void *conn_user_data)
{
    (void)conn;
    (void)cid;
    (void)err_code;

    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)conn_user_data;
    if (user_session == NULL) {
        return 0;
    }

    xqc_moq_relay_conn_t *conn_ctx = (xqc_moq_relay_conn_t *)user_session->data;
    if (conn_ctx != NULL) {
        conn_ctx->base.closing_notified = 1;
    }

    xqc_moq_session_t *closing_session = user_session->session;
    if (closing_session != NULL) {
        xqc_moq_relay_detach_session_from_forwardings(closing_session);
        xqc_moq_relay_detach_pub_namespaces(closing_session);
    }

    if (conn_ctx != NULL && !xqc_list_empty(&conn_ctx->list_member)) {
        xqc_list_del_init(&conn_ctx->list_member);
    }

    return 0;
}

static void
xqc_moq_relay_on_session_setup(xqc_moq_user_session_t *user_session, char *extdata,
    const xqc_moq_message_parameter_t *params, uint64_t params_num)
{
    (void)extdata;
    if (user_session == NULL || user_session->session == NULL) {
        return;
    }

    xqc_moq_session_t *session = user_session->session;
    xqc_moq_relay_conn_t *conn_ctx = (xqc_moq_relay_conn_t *)user_session->data;
    conn_ctx->session = session;

    if (params != NULL && params_num > 0) {
        for (uint64_t i = 0; i < params_num; i++) {
            if (params[i].type == XQC_MOQ_PARAM_ROLE && params[i].is_integer) {
                session->peer_role = (xqc_moq_role_t)params[i].int_value;
            }
        }
    }

    printf("relay session setup: peer_role:%u\n", (unsigned)session->peer_role);
}

static void
xqc_moq_relay_on_datachannel(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_track_info_t *track_info)
{
    (void)user_session;
    (void)track;
    (void)track_info;
}

static void
xqc_moq_relay_on_datachannel_msg(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_track_info_t *track_info, uint8_t *msg, size_t msg_len)
{
    (void)user_session;
    (void)track;
    (void)track_info;
    (void)msg;
    (void)msg_len;
}

static void
xqc_moq_relay_on_subscribe(xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
    xqc_moq_track_t *track, xqc_moq_subscribe_msg_t *msg)
{
    if (track != NULL) {
        return;
    }
    if (user_session == NULL || user_session->session == NULL || msg == NULL) {
        return;
    }

    xqc_moq_session_t *session = user_session->session;

    xqc_moq_relay_pub_namespace_t *pub_ns = xqc_moq_relay_find_pub_namespace_for_track(
        msg->track_namespace_tuple, msg->track_namespace_num, session);

    if (pub_ns != NULL) {
        printf("relay on_subscribe: found publisher for namespace, sending subscribe_ok "
               "subscribe_id:%"PRIu64" track:%s\n",
               subscribe_id, msg->track_name ? msg->track_name : "null");
        xqc_moq_subscribe_ok_msg_t ok;
        memset(&ok, 0, sizeof(ok));
        ok.subscribe_id = subscribe_id;
        ok.expire_ms = 0;
        ok.content_exist = 0;
        ok.largest_group_id = 0;
        ok.largest_object_id = 0;
        ok.params_num = 0;
        ok.params = NULL;
        xqc_moq_write_subscribe_ok(session, &ok);
    } else {
        printf("relay on_subscribe: no publisher found, sending subscribe_error "
               "subscribe_id:%"PRIu64" track:%s\n",
               subscribe_id, msg->track_name ? msg->track_name : "null");
        xqc_moq_subscribe_error_msg_t err;
        memset(&err, 0, sizeof(err));
        err.subscribe_id = subscribe_id;
        err.error_code = 1;
        err.reason_phrase = "no matching publisher namespace";
        err.reason_phrase_len = strlen(err.reason_phrase);
        err.track_alias = msg->track_alias;
        xqc_moq_write_subscribe_error(session, &err);
    }
}

static void
xqc_moq_relay_on_subscribe_ok(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_track_info_t *track_info, xqc_moq_subscribe_ok_msg_t *subscribe_ok)
{
    (void)user_session;
    (void)track;
    (void)track_info;
    (void)subscribe_ok;
}

static void
xqc_moq_relay_on_subscribe_error(xqc_moq_user_session_t *user_session, xqc_moq_track_t *track,
    xqc_moq_track_info_t *track_info, xqc_moq_subscribe_error_msg_t *subscribe_error)
{
    (void)user_session;
    (void)track;
    (void)track_info;
    (void)subscribe_error;
}

static void
xqc_moq_relay_on_request_keyframe(xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
    xqc_moq_track_t *track)
{
    (void)user_session;
    (void)subscribe_id;
    (void)track;
}

static void
xqc_moq_relay_on_catalog(xqc_moq_user_session_t *user_session, xqc_moq_track_info_t **track_info_array,
    xqc_int_t array_size)
{
    (void)user_session;
    (void)track_info_array;
    (void)array_size;
}

static void
xqc_server_socket_read_handler(xqc_app_ctx_t *ctx)
{
    unsigned char packet_buf[2048];
    struct sockaddr_in6 peer_addr;
    socklen_t peer_addrlen = sizeof(peer_addr);

    ssize_t recv_size;
    do {
        recv_size = recvfrom(ctx->listen_fd, packet_buf, sizeof(packet_buf), 0,
                             (struct sockaddr *)&peer_addr, &peer_addrlen);
        if (recv_size < 0) {
            break;
        }
        xqc_int_t ret = xqc_engine_packet_process(ctx->engine, packet_buf, (size_t)recv_size,
                                                  (struct sockaddr *)&ctx->local_addr, ctx->local_addrlen,
                                                  (struct sockaddr *)&peer_addr, peer_addrlen,
                                                  xqc_now(), NULL);
        if (ret != XQC_OK) {
            printf("xqc_engine_packet_process error:%d\n", ret);
            break;
        }
    } while (recv_size > 0);

    xqc_engine_finish_recv(ctx->engine);
}

static void
xqc_server_socket_write_handler(xqc_app_ctx_t *ctx)
{
    (void)ctx;
}

static void
xqc_server_socket_event_callback(int fd, short what, void *arg)
{
    xqc_app_ctx_t *ctx = (xqc_app_ctx_t *)arg;
    if (what & EV_READ) {
        xqc_server_socket_read_handler(ctx);
    } else if (what & EV_WRITE) {
        xqc_server_socket_write_handler(ctx);
    }
}

static void
stop(int signo)
{
    (void)signo;
    event_base_loopbreak(g_event_base);
    xqc_engine_destroy(g_app_ctx.engine);
    fflush(stdout);
    exit(0);
}

static int
xqc_server_create_socket(const char *addr, unsigned int port)
{
    int fd;
    int type = g_ipv6 ? AF_INET6 : AF_INET;
    g_app_ctx.local_addrlen = g_ipv6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);

    memset(&g_app_ctx.local_addr, 0, sizeof(g_app_ctx.local_addr));
    struct sockaddr_in6 *sin6 = &g_app_ctx.local_addr;
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port = htons(port);
    if (g_ipv6) {
        inet_pton(AF_INET6, addr, &sin6->sin6_addr);
    } else {
        struct sockaddr_in *sin = (struct sockaddr_in *)&g_app_ctx.local_addr;
        sin->sin_family = AF_INET;
        sin->sin_port = htons(port);
        sin->sin_addr.s_addr = inet_addr(addr);
    }

    fd = socket(type, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("create socket failed, errno:%d\n", get_sys_errno());
        return -1;
    }
#ifndef XQC_SYS_WINDOWS
    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        printf("set socket nonblock failed, errno:%d\n", errno);
        close(fd);
        return -1;
    }
#endif
    int optval = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

    if (bind(fd, (struct sockaddr *)&g_app_ctx.local_addr, g_app_ctx.local_addrlen) < 0) {
        printf("bind failed, errno:%d\n", get_sys_errno());
        close(fd);
        return -1;
    }
    return fd;
}

static int
xqc_server_accept(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data)
{
    (void)engine;
    (void)user_data;

    xqc_moq_user_session_t *user_session = calloc(1, sizeof(xqc_moq_user_session_t) + sizeof(xqc_moq_relay_conn_t));
    if (user_session == NULL) {
        return -1;
    }
    xqc_moq_relay_conn_t *conn_ctx = (xqc_moq_relay_conn_t *)user_session->data;
    conn_ctx->user_session = user_session;
    conn_ctx->conn = conn;
    conn_ctx->base.fd = g_app_ctx.listen_fd;
    memcpy(&conn_ctx->cid, cid, sizeof(*cid));
    xqc_init_list_head(&conn_ctx->list_member);
    xqc_list_add_tail(&conn_ctx->list_member, &g_relay_conn_list);

    xqc_moq_session_callbacks_t callbacks = {
        .on_session_setup = xqc_moq_relay_on_session_setup,
        .on_datachannel = xqc_moq_relay_on_datachannel,
        .on_datachannel_msg = xqc_moq_relay_on_datachannel_msg,
        .on_subscribe = xqc_moq_relay_on_subscribe,
        .on_request_keyframe = xqc_moq_relay_on_request_keyframe,
        .on_subscribe_ok = xqc_moq_relay_on_subscribe_ok,
        .on_subscribe_error = xqc_moq_relay_on_subscribe_error,
        .on_publish = xqc_moq_relay_on_publish,
        .on_publish_ok = xqc_moq_relay_on_publish_ok,
        .on_publish_done = xqc_moq_relay_on_publish_done,
        .on_catalog = xqc_moq_relay_on_catalog,
        .on_video = xqc_moq_relay_on_video_frame,
        .on_audio = xqc_moq_relay_on_audio_frame,
        .on_publish_namespace = xqc_moq_relay_on_publish_namespace,
        .on_subscribe_namespace = xqc_moq_relay_on_subscribe_namespace,
    };

    xqc_moq_session_t *session = xqc_moq_session_create(conn, user_session, XQC_MOQ_TRANSPORT_QUIC,
        XQC_MOQ_PUBSUB, callbacks, NULL, g_enable_client_setup_v14);
    if (session == NULL) {
        printf("relay create session error\n");
        xqc_list_del(&conn_ctx->list_member);
        free(user_session);
        return -1;
    }
    conn_ctx->session = session;

    xqc_conn_set_transport_user_data(conn, user_session);
    printf("relay accept: session:%p\n", (void *)session);
    return 0;
}

static int
xqc_server_conn_close_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data)
{
    (void)conn;
    (void)cid;
    (void)conn_proto_data;

    xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
    if (user_session == NULL) {
        return 0;
    }

    xqc_moq_relay_conn_t *conn_ctx = (xqc_moq_relay_conn_t *)user_session->data;
    xqc_moq_session_t *closing_session = conn_ctx ? conn_ctx->session : NULL;
    if (closing_session != NULL) {
        xqc_moq_relay_detach_session_from_forwardings(closing_session);
        xqc_moq_relay_detach_pub_namespaces(closing_session);
    }

    if (conn_ctx != NULL && !xqc_list_empty(&conn_ctx->list_member)) {
        xqc_list_del_init(&conn_ctx->list_member);
    }

    if (user_session->session != NULL) {
        xqc_moq_session_destroy(user_session->session);
    }
    free(user_session);
    return 0;
}

int
main(int argc, char *argv[])
{
    signal(SIGINT, stop);
    signal(SIGTERM, stop);

    int ch;
    while ((ch = getopt(argc, argv, "p:l:V")) != -1) {
        switch (ch) {
        case 'p':
            g_relay_port = atoi(optarg);
            printf("option port :%s\n", optarg);
            break;
        case 'l':
            g_log_level = optarg[0];
            printf("option log level :%s\n", optarg);
            break;
        case 'V':
            printf("option draft14 client setup : on\n");
            g_enable_client_setup_v14 = 1;
            break;
        default:
            break;
        }
    }

    memset(&g_app_ctx, 0, sizeof(g_app_ctx));
    xqc_init_list_head(&g_relay_conn_list);
    xqc_init_list_head(&g_relay_forwarding_list);
    xqc_init_list_head(&g_relay_pub_namespace_list);

    xqc_app_open_log_file(&g_app_ctx, "./relay.log");
    xqc_platform_init_env();

    xqc_engine_ssl_config_t engine_ssl_config;
    memset(&engine_ssl_config, 0, sizeof(engine_ssl_config));
    engine_ssl_config.private_key_file = "./server.key";
    engine_ssl_config.cert_file = "./server.crt";
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;

    xqc_config_t config;
    if (xqc_engine_get_default_config(&config, XQC_ENGINE_SERVER) < 0) {
        return -1;
    }
    xqc_app_set_log_level(g_log_level, &config);

    xqc_engine_callback_t engine_callbacks = {
        .set_event_timer = xqc_app_set_event_timer,
        .log_callbacks = {
            .xqc_log_write_err = xqc_app_write_log,
            .xqc_log_write_stat = xqc_app_write_log,
        },
    };

    xqc_transport_callbacks_t transport_callbacks = {
        .server_accept = xqc_server_accept,
        .write_socket = xqc_app_write_socket,
        .write_socket_ex = xqc_app_write_socket_ex,
        .conn_closing = xqc_server_conn_closing_notify,
    };

    g_app_ctx.engine = xqc_engine_create(XQC_ENGINE_SERVER, &config, &engine_ssl_config,
        &engine_callbacks, &transport_callbacks, &g_app_ctx);
    if (g_app_ctx.engine == NULL) {
        printf("create engine error\n");
        return -1;
    }

    xqc_conn_callbacks_t conn_cbs = {
        .conn_create_notify = NULL,
        .conn_close_notify = xqc_server_conn_close_notify,
        .conn_handshake_finished = NULL,
    };
    xqc_moq_init_alpn(g_app_ctx.engine, &conn_cbs, XQC_MOQ_TRANSPORT_QUIC);

    g_app_ctx.listen_fd = xqc_server_create_socket(TEST_ADDR, (unsigned)g_relay_port);
    if (g_app_ctx.listen_fd < 0) {
        printf("create listen socket error\n");
        return -1;
    }

    g_event_base = event_base_new();
    if (g_event_base == NULL) {
        return -1;
    }
    g_app_ctx.ev_engine = event_new(g_event_base, -1, 0, xqc_app_engine_callback, &g_app_ctx);
    g_app_ctx.ev_socket = event_new(g_event_base, g_app_ctx.listen_fd, EV_READ | EV_PERSIST,
                                    xqc_server_socket_event_callback, &g_app_ctx);
    event_add(g_app_ctx.ev_socket, NULL);

    printf("moq_demo_relay_v14 listening on %s:%d\n", TEST_ADDR, g_relay_port);
    event_base_dispatch(g_event_base);

    xqc_engine_destroy(g_app_ctx.engine);
    return 0;
}
