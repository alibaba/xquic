/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 *
 * Fuzz target: the capsules of a WebTransport session's CONNECT stream
 * (RFC 9297 Section 3.2, draft-ietf-webtrans-http3-16 Sections 5 and 6).
 *
 * A draft-16 session is set up as in the WebTransport unit tests, with
 * session flow control when the first byte has bit 0 set; the next six
 * bytes are the peer's initial flow control limits. The rest is the
 * session stream, given in chunks of a length from the input; bit 1 ends
 * the stream with the last chunk.
 */

#include <stdlib.h>
#include <string.h>

#include "src/http3/xqc_h3_conn.h"
#include "src/transport/xqc_conn.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_ctx.h"
#include "src/webtransport/xqc_webtransport_session.h"
#include "xqc_fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    xqc_fuzz_input_t in = {data, size};
    xqc_wt_ctx_t ctx;
    xqc_h3_conn_t h3c;
    xqc_connection_t transport;
    xqc_wt_conn_t *conn;
    xqc_wt_session_t *session;
    xqc_h3_setting_t settings[6];
    const uint8_t *chunk;
    uint8_t *buf;
    uint8_t mode;
    size_t len, n = 0;
    xqc_bool_t fin;

    mode = xqc_fuzz_u8(&in);

    memset(&ctx, 0, sizeof(ctx));
    memset(&h3c, 0, sizeof(h3c));
    memset(&transport, 0, sizeof(transport));
    ctx.settings.draft_version = XQC_WEBTRANSPORT_DRAFT_VERSION_16;
    ctx.settings.max_sessions_count = (mode & 0x01) ? 4 : 1;
    ctx.settings.max_uni_streams = 8;
    ctx.settings.max_bidi_streams = 8;
    ctx.settings.init_recv_window = 65536;
    ctx.settings.enable_datagram = XQC_TRUE;
    h3c.conn = &transport;
    h3c.log = xqc_fuzz_log();
    transport.log = xqc_fuzz_log();
    transport.conn_type = XQC_CONN_TYPE_SERVER;
    transport.local_settings.max_datagram_frame_size = 1200;
    transport.remote_settings.max_datagram_frame_size = 1200;
    transport.local_settings.reset_stream_at = XQC_TRUE;
    transport.remote_settings.reset_stream_at = XQC_TRUE;

    conn = xqc_wt_conn_create(&h3c);
    if (conn == NULL) {
        return 0;
    }
    conn->ctx = &ctx;

    settings[n].identifier = XQC_WT_SETTING_CONNECT;
    settings[n++].value = 1;
    settings[n].identifier = XQC_WT_SETTING_DATAGRAM;
    settings[n++].value = 1;
    settings[n].identifier = XQC_WT_SETTING_ENABLED_16;
    settings[n++].value = 1;
    settings[n].identifier = XQC_WT_SETTING_INITIAL_MAX_STREAMS_UNI;
    settings[n++].value = xqc_fuzz_u16(&in);
    settings[n].identifier = XQC_WT_SETTING_INITIAL_MAX_STREAMS_BIDI;
    settings[n++].value = xqc_fuzz_u16(&in);
    settings[n].identifier = XQC_WT_SETTING_INITIAL_MAX_DATA;
    settings[n++].value = xqc_fuzz_u16(&in);
    if (xqc_wt_conn_peer_settings(&h3c, settings, n, NULL)
        != XQC_H3_SETTINGS_ACCEPT)
    {
        goto end;
    }

    session = xqc_wt_session_init(0, conn, NULL);
    if (session == NULL) {
        goto end;
    }
    session->open = XQC_TRUE;

    while (in.size > 0) {
        len = xqc_fuzz_take(&in, xqc_fuzz_u8(&in) + 1, &chunk);
        fin = (mode & 0x02) && in.size == 0;

        /* a heap copy of the exact size, so that ASan catches overreads */
        buf = malloc(len);
        if (buf == NULL) {
            break;
        }
        memcpy(buf, chunk, len);
        if (xqc_wt_session_recv_capsules(session, buf, len, fin) != XQC_OK) {
            free(buf);
            break;
        }
        free(buf);
    }

end:
    xqc_wt_conn_destroy(conn);
    return 0;
}
