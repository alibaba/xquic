/**
 * xqc_webtransport_msg.h
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#ifndef XQC_WEBTRANSPORT_MSG_H
#define XQC_WEBTRANSPORT_MSG_H

#include <xquic/xqc_webtransport.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XQC_WT_MSG_VERSION_0 0
#define XQC_WT_MSG_FLAG_TEXT 0x01

typedef enum {
    XQC_WT_MSG_BINARY = 0,
    XQC_WT_MSG_TEXT = 1,
} xqc_wt_msg_type_t;

typedef struct xqc_wt_msg_stream_s xqc_wt_msg_stream_t;

/**
 * Complete-message receive notification.
 *
 * The payload is borrowed for this callback only. A recursive receive returns
 * -XQC_ESTATE. Destroying msg_stream is allowed; release is deferred until the
 * active receive returns and no later messages in that input are delivered.
 */
typedef void (*xqc_wt_msg_recv_notify_pt)(
    xqc_wt_msg_stream_t *msg_stream, xqc_wt_msg_type_t type,
    const void *data, size_t data_len, void *user_data);

/**
 * Create an optional message-framing wrapper for one bidirectional stream.
 *
 * The wrapper borrows stream. max_message_size is a nonzero payload bound for
 * both sending and receiving. recv_notify is required. On failure, err
 * receives a negative XQUIC error when it is non-NULL.
 *
 * The application may destroy the wrapper earlier when it no longer needs
 * framing, but must request destruction by the final stream-close callback.
 * If a synchronous callback destroys the wrapper during an active operation,
 * release is deferred until that operation returns.
 */
XQC_EXPORT_PUBLIC_API
xqc_wt_msg_stream_t *xqc_wt_msg_stream_create(
    xqc_wt_bidistream_t *stream, size_t max_message_size,
    xqc_wt_msg_recv_notify_pt recv_notify, void *user_data, int *err);

/**
 * Request release of the wrapper and its queued or partial message.
 *
 * This function does not close, reset, or otherwise modify the underlying
 * WebTransport stream. Release is deferred while a wrapper operation is
 * active.
 */
XQC_EXPORT_PUBLIC_API
void xqc_wt_msg_stream_destroy(xqc_wt_msg_stream_t *msg_stream);

/**
 * Copy and queue one complete binary or text message.
 *
 * XQC_OK means the wrapper accepted and copied the message; it does not mean
 * every byte reached the transport. -XQC_EAGAIN means a previous message is
 * still queued and the new message was not accepted. Applications must not
 * mix this operation with raw sends on the same bidirectional stream.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_wt_msg_stream_send_msg(xqc_wt_msg_stream_t *msg_stream,
    xqc_wt_msg_type_t type, const void *data, size_t data_len);

/**
 * Resume a queued message from wt_bidistream_write_notify.
 *
 * Blocking and positive short writes retain the unsent suffix and return
 * XQC_OK so the WebTransport write callback does not report a fatal error.
 * Other negative results are terminal for this wrapper's sending direction.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_wt_msg_stream_flush(xqc_wt_msg_stream_t *msg_stream);

/**
 * Queue FIN after the current message and finish the sending direction.
 *
 * This operation is idempotent. It returns XQC_OK when FIN has been queued;
 * xqc_wt_msg_stream_flush() resumes a blocked message or FIN. No later message
 * can be sent through this wrapper.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_wt_msg_stream_finish(xqc_wt_msg_stream_t *msg_stream);

/**
 * Consume one raw WebTransport read callback and deliver complete messages.
 *
 * The wrapper reads FIN from the bound stream. A negative parse result is an
 * application-protocol error; the application chooses the reset/stop-sending
 * code and must not propagate that result as a raw read-callback result.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_wt_msg_stream_recv_msg(xqc_wt_msg_stream_t *msg_stream,
    const void *data, size_t data_len);

#ifdef __cplusplus
}
#endif

#endif
