#ifndef _XQC_MOQ_DEMO_COMM_H_INCLUDED_
#define _XQC_MOQ_DEMO_COMM_H_INCLUDED_

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <memory.h>
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

#include "tests/platform.h"

#ifndef XQC_SYS_WINDOWS
#include <unistd.h>
#include <sys/wait.h>
#include <getopt.h>
#else
#include "getopt.h"
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#endif

#include <moq/xqc_moq.h>

extern int g_drop_rate;

/* Get timestamp string for logging */
static inline void xqc_get_timestamp(char *buf, size_t len) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *tm_info = localtime(&tv.tv_sec);
    snprintf(buf, len, "[%02d:%02d:%02d.%03d]", 
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec, (int)(tv.tv_usec / 1000));
}

typedef struct xqc_app_ctx_s {
    xqc_engine_t        *engine;
    int                  log_fd;

    /* For server*/
    int                  listen_fd;
    struct sockaddr_in6  local_addr;
    socklen_t            local_addrlen;
    struct event        *ev_socket;
    struct event        *ev_engine;
} xqc_app_ctx_t;

typedef struct user_conn_s {
    struct event        *ev_timeout;
    struct sockaddr     *peer_addr;
    socklen_t            peer_addrlen;
    struct sockaddr     *local_addr;
    socklen_t            local_addrlen;
    xqc_cid_t            cid;
    int                  fd;
    unsigned char       *token;
    unsigned             token_len;
    struct event        *ev_socket;
    int                  get_local_addr;

    //For Moq
    struct event        *ev_send_timer;
    struct event        *ev_announce_timer;
    xqc_moq_track_t     *audio_track;
    xqc_moq_track_t     *video_track;
    xqc_moq_track_t     *clock_track;
    xqc_moq_track_t     *default_track;
    xqc_moq_track_t     *dynamic_track;  /* For dynamically created track (stream3) */
    xqc_moq_session_t   *moq_session;
    uint64_t            video_subscribe_id;
    uint64_t            audio_subscribe_id;
    uint64_t            clock_subscribe_id;
    uint64_t            default_subscribe_id;
    uint64_t            video_seq;
    uint64_t            audio_seq;
    uint64_t            clock_seq;
    uint64_t            default_seq;
    int                 countdown;
    int                 request_keyframe;
    int                 closing_notified;
    int                 object_id;
    int                 stream1_subscribed;
    int                 stream2_subscribed;
    int                 stream3_subscribed;
    int                 stream3_message_count;
    int                 new_track_created;
    int                 namespace_subscribed;
    #define MAX_SUBGROUP_STREAMS 3
    struct {
        xqc_moq_stream_t *streams[MAX_SUBGROUP_STREAMS];
        uint64_t         group_ids[MAX_SUBGROUP_STREAMS];
        int              next_idx;
    } stream_pool;
} user_conn_t;


void
xqc_app_set_log_level(char c_log_level, xqc_config_t *config);

int
xqc_app_open_log_file(void *engine_user_data, const char *file_name);

int
xqc_app_read_file_data(unsigned char * data, size_t data_len, char *filename);

int 
xqc_app_delete_file(const char *filename);

void
xqc_app_engine_callback(int fd, short what, void *arg);

void
xqc_app_set_event_timer(xqc_usec_t wake_after, void *user_data);

void
xqc_app_write_log(xqc_log_level_t lvl, const void *buf, size_t count, void *engine_user_data);

ssize_t
xqc_app_write_socket(const unsigned char *buf, size_t size,
                     const struct sockaddr *peer_addr,
                     socklen_t peer_addrlen, void *user_data);

ssize_t
xqc_app_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size, 
                        const struct sockaddr *peer_addr,
                        socklen_t peer_addrlen, void *user_data);

#endif /* _XQC_MOQ_DEMO_COMM_H_INCLUDED_ */
