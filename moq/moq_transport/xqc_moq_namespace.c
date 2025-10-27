#include "moq/moq_transport/xqc_moq_namespace.h"
#include "src/common/xqc_malloc.h"
#include "src/common/xqc_log.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include <string.h>
#include "moq/moq_transport/xqc_moq_track.h"

static xqc_moq_msg_track_namespace_t *
xqc_moq_namespace_clone_prefix(xqc_moq_msg_track_namespace_t *src)
{
    if (src == NULL) {
        return NULL;
    }
    xqc_moq_msg_track_namespace_t *dst = xqc_calloc(1, sizeof(xqc_moq_msg_track_namespace_t));
    if (dst == NULL) return NULL;
    dst->track_namespace_num = src->track_namespace_num;
    if (dst->track_namespace_num > 0) {
        dst->track_namespace_len = xqc_calloc(dst->track_namespace_num, sizeof(uint64_t));
        dst->track_namespace = xqc_calloc(dst->track_namespace_num, sizeof(char*));
        if (dst->track_namespace_len == NULL || dst->track_namespace == NULL) {
            return NULL;
        }
        for (uint64_t i = 0; i < dst->track_namespace_num; i++) {
            dst->track_namespace_len[i] = src->track_namespace_len[i];
            dst->track_namespace[i] = xqc_calloc(1, dst->track_namespace_len[i] + 1);
            if (dst->track_namespace[i] == NULL) {
                return NULL;
            }
            memcpy(dst->track_namespace[i], src->track_namespace[i], dst->track_namespace_len[i]);
        }
    }
    return dst;
}

static void
xqc_moq_namespace_free_prefix(xqc_moq_msg_track_namespace_t *ns)
{
    if (ns == NULL) return;
    if (ns->track_namespace) {
        for (uint64_t i = 0; i < ns->track_namespace_num; i++) {
            xqc_free(ns->track_namespace[i]);
        }
        xqc_free(ns->track_namespace);
    }
    xqc_free(ns->track_namespace_len);
    xqc_free(ns);
}

void
xqc_moq_namespace_watch_add(xqc_moq_session_t *session, uint64_t request_id,
    xqc_moq_msg_track_namespace_t *prefix)
{
    xqc_moq_namespace_watch_t *watch = xqc_calloc(1, sizeof(xqc_moq_namespace_watch_t));
    if (watch == NULL) return;
    watch->request_id = request_id;
    watch->prefix = xqc_moq_namespace_clone_prefix(prefix);
    xqc_init_list_head(&watch->list_member);
    xqc_list_add_tail(&watch->list_member, &session->namespace_watch_list);
}

void
xqc_moq_namespace_watch_remove_by_prefix(xqc_moq_session_t *session,
    xqc_moq_msg_track_namespace_t *prefix)
{
    xqc_list_head_t *pos, *next;
    xqc_moq_namespace_watch_t *watch;
    xqc_list_for_each_safe(pos, next, &session->namespace_watch_list) {
        watch = (xqc_moq_namespace_watch_t *)xqc_list_entry(pos, xqc_moq_namespace_watch_t, list_member);
        if (watch->prefix && prefix && watch->prefix->track_namespace_num == prefix->track_namespace_num) {
            xqc_bool_t equal = 1;
            for (uint64_t i = 0; i < prefix->track_namespace_num; i++) {
                if (watch->prefix->track_namespace_len[i] != prefix->track_namespace_len[i]
                    || strncmp(watch->prefix->track_namespace[i], prefix->track_namespace[i], prefix->track_namespace_len[i]) != 0) {
                    equal = 0;
                    break;
                }
            }
            if (equal) {
                xqc_list_del(pos);
                xqc_moq_namespace_free_prefix(watch->prefix);
                xqc_free(watch);
            }
        }
    }
}

void
xqc_moq_namespace_free_all(xqc_moq_session_t *session)
{
    xqc_list_head_t *pos, *next;
    xqc_moq_namespace_watch_t *watch;
    xqc_list_for_each_safe(pos, next, &session->namespace_watch_list) {
        watch = (xqc_moq_namespace_watch_t *)xqc_list_entry(pos, xqc_moq_namespace_watch_t, list_member);
        xqc_list_del(pos);
        xqc_moq_namespace_free_prefix(watch->prefix);
        xqc_free(watch);
    }
}

xqc_int_t
xqc_moq_namespace_prefix_match(xqc_moq_msg_track_namespace_t *prefix,
    const char *track_namespace)
{
    if (prefix == NULL || track_namespace == NULL) return 0;
    if (prefix->track_namespace_num == 0) return 0;
    const char *pre = prefix->track_namespace[0];
    if (pre == NULL) return 0;
    size_t len = prefix->track_namespace_len[0];
    if (strlen(track_namespace) < len) return 0;
    return strncmp(track_namespace, pre, len) == 0;
}

void
xqc_moq_namespace_notify_on_track_added(xqc_moq_session_t *session, xqc_moq_track_t *track)
{
    if (track == NULL || track->track_info.track_namespace == NULL || track->track_info.track_name == NULL) {
        xqc_log(session->log, XQC_LOG_WARN, "|ns_notify_on_track_added|track_null_or_invalid|");
        return;
    }
    
    xqc_log(session->log, XQC_LOG_INFO, "|ns_notify_on_track_added|track:%s/%s|alias:%llu|",
            track->track_info.track_namespace, track->track_info.track_name,
            (unsigned long long)track->track_alias);
    
    if (xqc_list_empty(&session->namespace_watch_list)) {
        xqc_log(session->log, XQC_LOG_INFO, "|ns_notify_on_track_added|watch_list_empty|");
        return;
    }
    
    xqc_list_head_t *pos, *next;
    xqc_moq_namespace_watch_t *watch;
    int watch_count = 0;
    int match_count = 0;
    xqc_list_for_each_safe(pos, next, &session->namespace_watch_list) {
        watch = (xqc_moq_namespace_watch_t *)xqc_list_entry(pos, xqc_moq_namespace_watch_t, list_member);
        watch_count++;
        
        xqc_log(session->log, XQC_LOG_INFO, 
                "|ns_checking_watch|watch#%d|request_id:%llu|prefix:%s|",
                watch_count, watch->request_id,
                watch->prefix && watch->prefix->track_namespace_num > 0 ? watch->prefix->track_namespace[0] : "NULL");
        
        if (!xqc_moq_namespace_prefix_match(watch->prefix, track->track_info.track_namespace)) {
            xqc_log(session->log, XQC_LOG_INFO, "|ns_prefix_not_match|");
            continue;
        }
        
        match_count++;
        xqc_log(session->log, XQC_LOG_INFO,
                "|ns_auto_publish|request_id:%llu|track:%s/%s|alias:%llu|",
                watch->request_id,
                track->track_info.track_namespace,
                track->track_info.track_name,
                (unsigned long long)track->track_alias);
        
        /* Construct PUBLISH message */
        xqc_moq_publish_msg_t publish_msg;
        memset(&publish_msg, 0, sizeof(publish_msg));
        publish_msg.request_id = watch->request_id;
        publish_msg.track_alias = track->track_alias;
        publish_msg.track_name = track->track_info.track_name;
        publish_msg.track_name_len = strlen(track->track_info.track_name);
        
        /* Construct namespace */
        publish_msg.track_namespace = xqc_calloc(1, sizeof(xqc_moq_msg_track_namespace_t));
        if (publish_msg.track_namespace == NULL) {
            xqc_log(session->log, XQC_LOG_ERROR, "|ns_auto_publish_alloc_failed|");
            continue;
        }
        
        publish_msg.track_namespace->track_namespace_num = 1;
        publish_msg.track_namespace->track_namespace = xqc_calloc(1, sizeof(char*));
        publish_msg.track_namespace->track_namespace_len = xqc_calloc(1, sizeof(uint64_t));
        
        if (publish_msg.track_namespace->track_namespace == NULL || 
            publish_msg.track_namespace->track_namespace_len == NULL) {
            xqc_free(publish_msg.track_namespace);
            xqc_log(session->log, XQC_LOG_ERROR, "|ns_auto_publish_alloc_failed|");
            continue;
        }
        
        publish_msg.track_namespace->track_namespace[0] = track->track_info.track_namespace;
        publish_msg.track_namespace->track_namespace_len[0] = strlen(track->track_info.track_namespace);
        
        publish_msg.group_order = 0;
        publish_msg.content_exists = 1;
        publish_msg.forward = 0;
        publish_msg.params_num = 0;
        publish_msg.params = NULL;
        
        /* Send PUBLISH */
        xqc_int_t ret = xqc_moq_publish(session, &publish_msg);
        if (ret < 0) {
            xqc_log(session->log, XQC_LOG_ERROR,
                    "|ns_auto_publish_failed|request_id:%llu|ret:%d|",
                    watch->request_id, ret);
        } else {
            xqc_log(session->log, XQC_LOG_INFO,
                    "|ns_auto_publish_sent|request_id:%llu|track:%s/%s|ret:%d|",
                    watch->request_id, track->track_info.track_namespace, 
                    track->track_info.track_name, ret);
        }
        
        xqc_free(publish_msg.track_namespace->track_namespace);
        xqc_free(publish_msg.track_namespace->track_namespace_len);
        xqc_free(publish_msg.track_namespace);
    }
    
    xqc_log(session->log, XQC_LOG_INFO, "|ns_notify_on_track_added_done|matches:%d|", match_count);
}

void
xqc_moq_namespace_notify_on_track_removed(xqc_moq_session_t *session, xqc_moq_track_t *track)
{
    xqc_list_head_t *pos, *next;
    xqc_moq_namespace_watch_t *watch;
    xqc_int_t done_sent = 0;
    xqc_list_for_each_safe(pos, next, &session->namespace_watch_list) {
        watch = (xqc_moq_namespace_watch_t *)xqc_list_entry(pos, xqc_moq_namespace_watch_t, list_member);
        if (!xqc_moq_namespace_prefix_match(watch->prefix, track->track_info.track_namespace)) {
            continue;
        }
        xqc_log(session->log, XQC_LOG_INFO,
                "|ns notify remove|prefix:%s|track:%s/%s|\n",
                watch->prefix->track_namespace[0], track->track_info.track_namespace, track->track_info.track_name);
        if (!done_sent && track->subscribe_id != XQC_MOQ_INVALID_ID) {
            xqc_moq_subscribe_done(session, track->subscribe_id,
                XQC_MOQ_STATUS_TRACK_ENDED, 0, "track ended", strlen("track ended"));
            done_sent = 1;
            xqc_moq_track_set_subscribe_id(track, XQC_MOQ_INVALID_ID);
        }
    }
}



