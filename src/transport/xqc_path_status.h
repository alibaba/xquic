/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_PATH_STATUS_H
#define XQC_PATH_STATUS_H

#include <xquic/xquic_typedef.h>

/*
 * Path status (RFC 10069 Section 3.3): each endpoint indicates its
 * preference for a path independently of the other, so the status this
 * endpoint indicates and the one the peer indicates are kept apart.
 */

/* a Path Status Sequence Number (RFC 10069 Section 4.3) */
typedef uint64_t xqc_path_status_seq_t;

/* the status this endpoint indicates for a path */
typedef struct {
    /* what the application asks for, see xqc_conn_mark_path_standby() */
    xqc_app_path_status_t   wanted;
    /*
     * what the last status frame sent says; before the first one, the peer
     * knows no preference and uses the path as an available one
     */
    xqc_app_path_status_t   advertised;
    /* the sequence number of the last one, 0 before it */
    xqc_path_status_seq_t   send_seq;
} xqc_path_local_status_t;

/* the status the peer indicates for a path ID */
typedef struct {
    /* XQC_APP_PATH_STATUS_NONE until the peer indicates one */
    xqc_app_path_status_t   status;
    /* whether a status frame was received, and its largest sequence number */
    xqc_bool_t              seq_received;
    xqc_path_status_seq_t   largest_seq;
} xqc_path_peer_status_t;

/*
 * RFC 10069 Section 4.3: a status frame is ignored if a frame with an equal
 * or higher Path Status Sequence Number was received before for the path
 * ID; nothing was received before the first one, whatever its number.
 * Returns whether the frame is applied.
 */
static inline xqc_bool_t
xqc_path_peer_status_update(xqc_path_peer_status_t *peer,
    xqc_path_status_seq_t seq, xqc_app_path_status_t status)
{
    if (peer->seq_received && seq <= peer->largest_seq) {
        return XQC_FALSE;
    }

    peer->seq_received = XQC_TRUE;
    peer->largest_seq = seq;
    peer->status = status;
    return XQC_TRUE;
}

#endif /* XQC_PATH_STATUS_H */
