#ifndef _XQC_TIMER_H_INCLUDED_
#define _XQC_TIMER_H_INCLUDED_

#include "src/common/xqc_time.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_packet_in.h"
#include "src/common/xqc_list.h"

/*
 * A connection will time out if no packets are sent or received for a
 * period longer than the time specified in the max_idle_timeout transport
 * parameter (see Section 10).  However, state in middleboxes might time
 * out earlier than that.  Though REQ-5 in [RFC4787] recommends a 2
 * minute timeout interval, experience shows that sending packets every
 * 15 to 30 seconds is necessary to prevent the majority of middleboxes
 * from losing state for UDP flows.
 */
#define XQC_PING_TIMEOUT                    15000

#define XQC_PMTUD_START_DELAY               10000

typedef enum xqc_timer_level {
    XQC_PATH_LEVEL_TIMER,
    XQC_CONN_LEVEL_TIMER,
} xqc_timer_level_t;

/* !!warning add to timer_type_2_str */
typedef enum xqc_timer_type {

    /* path level (path->path_send_ctl->path_timer_manager->timer[XQC_TIMER_N])*/
    XQC_TIMER_ACK_INIT,
    XQC_TIMER_ACK_HSK   = XQC_TIMER_ACK_INIT + XQC_PNS_HSK,
    XQC_TIMER_ACK_01RTT = XQC_TIMER_ACK_INIT + XQC_PNS_APP_DATA,
    XQC_TIMER_LOSS_DETECTION,
    XQC_TIMER_PACING,
    XQC_TIMER_NAT_REBINDING,
    XQC_TIMER_PATH_IDLE,
    XQC_TIMER_PATH_DRAINING,

    /* connection level (conn->conn_timer_manager->timer[XQC_TIMER_N]) */
    XQC_TIMER_CONN_IDLE,
    XQC_TIMER_CONN_DRAINING,
    XQC_TIMER_STREAM_CLOSE,
    XQC_TIMER_PING,
    XQC_TIMER_RETIRE_CID,
    XQC_TIMER_LINGER_CLOSE,
    XQC_TIMER_KEY_UPDATE,
    XQC_TIMER_PMTUD_PROBING,

    XQC_TIMER_N,

} xqc_timer_type_t;

typedef int32_t xqc_gp_timer_id_t;

#define XQC_GP_TIMER_ID_MAX (0x7fffffff)

/* timer timeout callback */
typedef void (*xqc_timer_timeout_pt)(xqc_timer_type_t type, xqc_usec_t now, void *user_data);

typedef void (*xqc_gp_timer_timeout_pt)(xqc_gp_timer_id_t gp_timer_id, xqc_usec_t now, void *user_data);

typedef struct xqc_timer_s {
    uint8_t                     timer_is_set;
    xqc_usec_t                  expire_time;

    /* callback function and user_data */
    xqc_timer_timeout_pt        timeout_cb;
    void                       *user_data;
} xqc_timer_t;

/* general purpose timer */
typedef struct xqc_gp_timer_s {
    xqc_list_head_t             list;
    xqc_gp_timer_id_t           id;
    xqc_bool_t                  timer_is_set;
    xqc_usec_t                  expire_time;

    /* callback function and user_data */
    xqc_gp_timer_timeout_pt     timeout_cb;
    void                       *user_data;
    char                       *name;
} xqc_gp_timer_t;

typedef struct xqc_timer_manager_s {
    xqc_timer_t                 timer[XQC_TIMER_N];
    xqc_log_t                  *log;
    /* general purpose timer */
    xqc_list_head_t             gp_timer_list;
    xqc_gp_timer_id_t           next_gp_timer_id;
} xqc_timer_manager_t;

/* APIs for gp timer */
xqc_gp_timer_id_t xqc_timer_register_gp_timer(xqc_timer_manager_t *manager, 
    char *timer_name, xqc_gp_timer_timeout_pt cb, void *user_data);

xqc_int_t xqc_timer_unregister_gp_timer(xqc_timer_manager_t *manager, xqc_gp_timer_id_t gp_timer_id);

void xqc_timer_destroy_gp_timer(xqc_gp_timer_t *gp_timer);

void xqc_timer_destroy_gp_timer_list(xqc_timer_manager_t *manager);

static inline xqc_int_t
xqc_timer_gp_timer_set(xqc_timer_manager_t *manager, xqc_gp_timer_id_t gp_timer_id, xqc_usec_t expire_time)
{
    if (!manager || gp_timer_id >= manager->next_gp_timer_id) {
        return -XQC_EPARAM;
    }

    xqc_list_head_t *pos, *next;
    xqc_gp_timer_t *gp_timer;

    xqc_list_for_each_safe(pos, next, &manager->gp_timer_list) {
        gp_timer = xqc_list_entry(pos, xqc_gp_timer_t, list);
        if (gp_timer->id == gp_timer_id) {
            gp_timer->expire_time = expire_time;
            gp_timer->timer_is_set = XQC_TRUE;
            xqc_log(manager->log, XQC_LOG_DEBUG, "|gp_timer_set|id:%d|name:%s|expire_time:%ui|", 
                    gp_timer->id, gp_timer->name, gp_timer->expire_time);
            return XQC_OK;
        }
    }
    return XQC_ERROR;
}

static inline xqc_int_t
xqc_timer_gp_timer_unset(xqc_timer_manager_t *manager, xqc_gp_timer_id_t gp_timer_id)
{
    if (!manager || gp_timer_id >= manager->next_gp_timer_id) {
        return -XQC_EPARAM;
    }

    xqc_list_head_t *pos, *next;
    xqc_gp_timer_t *gp_timer;

    xqc_list_for_each_safe(pos, next, &manager->gp_timer_list) {
        gp_timer = xqc_list_entry(pos, xqc_gp_timer_t, list);
        if (gp_timer->id == gp_timer_id) {
            gp_timer->expire_time = 0;
            gp_timer->timer_is_set = XQC_FALSE;
            xqc_log(manager->log, XQC_LOG_DEBUG, "|gp_timer_unset|id:%d|name:%s|expire_time:%ui|", 
                    gp_timer->id, gp_timer->name, gp_timer->expire_time);
            return XQC_OK;
        }
    }
    return XQC_ERROR;
}

static inline xqc_int_t
xqc_timer_gp_timer_get_info(xqc_timer_manager_t *manager, xqc_gp_timer_id_t gp_timer_id, xqc_bool_t *is_set, xqc_usec_t *expire_time)
{
    if (!manager || gp_timer_id >= manager->next_gp_timer_id) {
        return -XQC_EPARAM;
    }

    xqc_list_head_t *pos, *next;
    xqc_gp_timer_t *gp_timer;

    xqc_list_for_each_safe(pos, next, &manager->gp_timer_list) {
        gp_timer = xqc_list_entry(pos, xqc_gp_timer_t, list);
        if (gp_timer->id == gp_timer_id) {
            *is_set = gp_timer->timer_is_set;
            *expire_time = gp_timer->expire_time;
            xqc_log(manager->log, XQC_LOG_DEBUG, "|gp_timer_get_info|id:%d|name:%s|is_set:%d|expire_time:%ui|", 
                    gp_timer->id, gp_timer->name, gp_timer->timer_is_set, gp_timer->expire_time);
            return XQC_OK;
        }
    }
    return XQC_ERROR;
}

const char *xqc_timer_type_2_str(xqc_timer_type_t timer_type);

void xqc_timer_init(xqc_timer_manager_t *manager, xqc_log_t *log, void *user_data);

static inline int
xqc_timer_is_set(xqc_timer_manager_t *manager, xqc_timer_type_t type)
{
    return manager->timer[type].timer_is_set;
}

static inline void
xqc_timer_set(xqc_timer_manager_t *manager, xqc_timer_type_t type, xqc_usec_t now, xqc_usec_t inter_time)
{
    manager->timer[type].timer_is_set = 1;
    manager->timer[type].expire_time = now + inter_time;
    xqc_log(manager->log, XQC_LOG_DEBUG, "|type:%s|expire:%ui|now:%ui|interv:%ui|",
            xqc_timer_type_2_str(type), manager->timer[type].expire_time, now, inter_time);
    xqc_log_event(manager->log, REC_LOSS_TIMER_UPDATED, manager, inter_time, (xqc_int_t) type, (xqc_int_t) XQC_LOG_TIMER_SET);
}

static inline void
xqc_timer_unset(xqc_timer_manager_t *manager, xqc_timer_type_t type)
{
    manager->timer[type].timer_is_set = 0;
    manager->timer[type].expire_time = 0;
    xqc_log(manager->log, XQC_LOG_DEBUG, "|type:%s|",
            xqc_timer_type_2_str(type));
    xqc_log_event(manager->log, REC_LOSS_TIMER_UPDATED, manager, 0, (xqc_int_t) type, (xqc_int_t) XQC_LOG_TIMER_CANCEL);
}

static inline void
xqc_timer_update(xqc_timer_manager_t *manager, xqc_timer_type_t type, xqc_usec_t now, xqc_usec_t inter_time)
{
    xqc_usec_t new_expire = now + inter_time;
    if (new_expire - manager->timer[type].expire_time < 1000) {
        return;
    }

    int was_set = manager->timer[type].timer_is_set;

    if (was_set) {
        /* update */
        manager->timer[type].expire_time = new_expire;
        xqc_log(manager->log, XQC_LOG_DEBUG, "|type:%s|new_expire:%ui|now:%ui|",
                xqc_timer_type_2_str(type), new_expire, xqc_monotonic_timestamp());

    } else {
        xqc_timer_set(manager, type, now, inter_time);
    }
}


static inline void
xqc_timer_expire(xqc_timer_manager_t *manager, xqc_usec_t now)
{
    xqc_timer_t *timer;
    for (xqc_timer_type_t type = 0; type < XQC_TIMER_N; ++type) {
        timer = &manager->timer[type];
        if (timer->timer_is_set && timer->expire_time <= now) {
            if (type == XQC_TIMER_CONN_IDLE) {
                xqc_log(manager->log, XQC_LOG_DEBUG,
                    "|conn:%p|timer expired|type:%s|expire_time:%ui|now:%ui|",
                    (xqc_connection_t *)timer->user_data, xqc_timer_type_2_str(type), timer->expire_time, now);

            } else {
                xqc_log(manager->log, XQC_LOG_DEBUG,
                    "|timer expired|type:%s|expire_time:%ui|now:%ui|",
                    xqc_timer_type_2_str(type), timer->expire_time, now);
            }

            xqc_log_event(manager->log, REC_LOSS_TIMER_UPDATED, manager, 0, (xqc_int_t) type, (xqc_int_t) XQC_LOG_TIMER_EXPIRE);

            timer->timeout_cb(type, now, timer->user_data);

            /* unset timer if it is not updated in timeout_cb */
            if (timer->expire_time <= now) {
                xqc_log(manager->log, XQC_LOG_DEBUG,
                        "|unset|type:%s|expire_time:%ui|now:%ui|",
                        xqc_timer_type_2_str(type), timer->expire_time, now);
                xqc_timer_unset(manager, type);
            }
        }
    }

    /* expire gp timer */
    xqc_list_head_t *pos, *next;
    xqc_gp_timer_t *gp_timer;

    xqc_list_for_each_safe(pos, next, &manager->gp_timer_list) {
        gp_timer = xqc_list_entry(pos, xqc_gp_timer_t, list);
        if (gp_timer->timer_is_set && gp_timer->expire_time <= now) {
            xqc_log(manager->log, XQC_LOG_DEBUG, "|gp_timer_expire|id:%d|name:%s|expire_time:%ui|now:%ui|", 
                    gp_timer->id, gp_timer->name, gp_timer->expire_time, now);
            gp_timer->timeout_cb(gp_timer->id, now, gp_timer->user_data);
            if (gp_timer->expire_time <= now) {
                xqc_timer_gp_timer_unset(manager, gp_timer->id);
            }
        }
    }
}

/*
 * *****************TIMER END*****************
 */


#endif /* _XQC_TIMER_H_INCLUDED_ */