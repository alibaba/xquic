/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 *
 * Fuzz target: HTTP/3 frames, SETTINGS and the Priority field.
 *
 * The first byte selects the parser:
 *
 *   even  the rest is the byte stream of an HTTP/3 stream, given to
 *         xqc_h3_frm_parse() in chunks of a length from the input; each
 *         complete SETTINGS frame goes to xqc_h3_frm_parse_setting() of an
 *         HTTP/3 client connection (RFC 9114 Section 7)
 *   odd   the rest is the value of a priority header field, for
 *         xqc_parse_http_priority() (RFC 9218 Section 4)
 */

#include <stdlib.h>
#include <string.h>

#include "src/http3/frame/xqc_h3_frame.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "xqc_fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);


static ssize_t
xqc_fuzz_write_socket(const unsigned char *buf, size_t size,
                      const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                      void *user_data)
{
    return (ssize_t)size;
}

/* an HTTP/3 client connection that has sent its first Initial */
static xqc_h3_conn_t *
xqc_fuzz_h3_conn(xqc_engine_t **engine)
{
    xqc_engine_ssl_config_t ssl_config;
    xqc_engine_callback_t callbacks;
    xqc_transport_callbacks_t transport_cbs;
    xqc_h3_callbacks_t h3_cbs;
    xqc_conn_settings_t settings;
    xqc_conn_ssl_config_t conn_ssl_config;
    xqc_config_t config;
    xqc_connection_t *conn;
    const xqc_cid_t *cid;

    xqc_fuzz_ssl_config(&ssl_config);
    xqc_fuzz_engine_callbacks(&callbacks);
    memset(&transport_cbs, 0, sizeof(transport_cbs));
    transport_cbs.write_socket = xqc_fuzz_write_socket;

    xqc_fuzz_engine_config(&config, XQC_ENGINE_CLIENT);

    *engine = xqc_engine_create(XQC_ENGINE_CLIENT, &config, &ssl_config,
                                &callbacks, &transport_cbs, NULL);
    if (*engine == NULL) {
        abort();
    }

    memset(&h3_cbs, 0, sizeof(h3_cbs));
    if (xqc_h3_ctx_init(*engine, &h3_cbs) != XQC_OK) {
        abort();
    }

    memset(&settings, 0, sizeof(settings));
    settings.proto_version = XQC_VERSION_V1;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));
    cid = xqc_h3_connect(*engine, &settings, NULL, 0, "", 0, &conn_ssl_config,
                         NULL, 0, NULL);
    if (cid == NULL) {
        abort();
    }

    conn = xqc_engine_conns_hash_find(*engine, cid, 's');
    if (conn == NULL || conn->proto_data == NULL) {
        abort();
    }

    return conn->proto_data;
}

static void
xqc_fuzz_h3_frames(xqc_fuzz_input_t *in)
{
    xqc_engine_t *engine;
    xqc_h3_conn_t *h3c;
    xqc_h3_frame_pctx_t pctx;
    xqc_var_buf_t *settings;
    const uint8_t *chunk;
    unsigned char *buf, *pos;
    uint64_t skip;
    ssize_t read;
    size_t len, left;

    h3c = xqc_fuzz_h3_conn(&engine);

    memset(&pctx, 0, sizeof(pctx));
    xqc_h3_frm_reset_pctx(&pctx);

    while (in->size > 0) {
        len = xqc_fuzz_take(in, xqc_fuzz_u8(in) + 1, &chunk);

        /* a heap copy of the exact size, so that ASan catches overreads */
        buf = malloc(len);
        if (buf == NULL) {
            break;
        }
        memcpy(buf, chunk, len);

        pos = buf;
        left = len;
        while (left > 0) {
            read = xqc_h3_frm_parse(pos, left, &pctx, h3c);
            if (read < 0) {
                free(buf);
                goto end;
            }
            if ((size_t)read > left) {
                abort();
            }
            pos += read;
            left -= read;

            /* the stream reads the payloads of DATA and HEADERS itself */
            skip = 0;
            if (pctx.state == XQC_H3_FRM_STATE_PAYLOAD
                && (pctx.frame.type == XQC_H3_FRM_DATA
                    || pctx.frame.type == XQC_H3_FRM_HEADERS))
            {
                skip = pctx.frame.len - pctx.frame.consumed_len;
                if (skip > left) {
                    skip = left;
                }
                pctx.frame.consumed_len += skip;
                pos += skip;
                left -= skip;
                if (pctx.frame.consumed_len == pctx.frame.len) {
                    pctx.state = XQC_H3_FRM_STATE_END;
                }
            }

            if (pctx.state == XQC_H3_FRM_STATE_END) {
                if (pctx.frame.type == XQC_H3_FRM_SETTINGS) {
                    settings = pctx.frame.frame_payload.settings.setting;
                    if (xqc_h3_frm_parse_setting(settings, h3c) < 0) {
                        free(buf);
                        goto end;
                    }
                }
                xqc_h3_frm_reset_pctx(&pctx);

            } else if (read == 0 && skip == 0) {
                break;
            }
        }

        free(buf);
    }

end:
    xqc_h3_frm_reset_pctx(&pctx);
    xqc_engine_destroy(engine);
}

static void
xqc_fuzz_h3_priority(xqc_fuzz_input_t *in)
{
    xqc_h3_priority_t prio;
    const uint8_t *value;
    uint8_t *buf, out[64];
    size_t len;

    len = xqc_fuzz_take(in, in->size, &value);

    /* a field value is not NUL-terminated */
    buf = malloc(len ? len : 1);
    if (buf == NULL) {
        return;
    }
    memcpy(buf, value, len);

    if (xqc_parse_http_priority(&prio, buf, len) == XQC_OK) {
        (void)xqc_write_http_priority(&prio, out, sizeof(out));
    }

    free(buf);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    xqc_fuzz_input_t in = {data, size};

    xqc_fuzz_now = XQC_FUZZ_START_TIME;
    if (xqc_fuzz_u8(&in) & 1) {
        xqc_fuzz_h3_priority(&in);

    } else {
        xqc_fuzz_h3_frames(&in);
    }

    return 0;
}
