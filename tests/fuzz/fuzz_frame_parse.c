/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 *
 * Fuzz target: the transport frame parsers of xqc_frame_parser.c.
 *
 * The input is the payload of a 1-RTT packet. Each frame is handed to the
 * parser that xqc_process_frames() would pick for its type, without
 * processing it, until a parser fails or the payload ends. FEC frames are
 * left out: their parsers need the FEC state of a negotiated connection.
 */

#include <stdlib.h>
#include <string.h>

#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/common/xqc_malloc.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_recv_record.h"
#include "src/transport/xqc_recv_timestamps_info.h"
#include "xqc_fuzz_common.h"

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static xqc_int_t xqc_fuzz_parse_frame(xqc_packet_in_t *packet_in,
                                      uint64_t frame_type);

static xqc_engine_t *xqc_fuzz_engine;
static xqc_connection_t *xqc_fuzz_conn;


static ssize_t
xqc_fuzz_write_socket(const unsigned char *buf, size_t size,
                      const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                      void *user_data)
{
    return (ssize_t)size;
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    xqc_engine_ssl_config_t ssl_config;
    xqc_engine_callback_t callbacks;
    xqc_transport_callbacks_t transport_cbs;
    xqc_app_proto_callbacks_t app_cbs;
    xqc_conn_settings_t settings;
    xqc_conn_ssl_config_t conn_ssl_config;
    xqc_config_t config;
    const xqc_cid_t *cid;

    xqc_fuzz_ssl_config(&ssl_config);
    xqc_fuzz_engine_callbacks(&callbacks);
    memset(&transport_cbs, 0, sizeof(transport_cbs));
    transport_cbs.write_socket = xqc_fuzz_write_socket;

    xqc_fuzz_engine_config(&config, XQC_ENGINE_CLIENT);

    xqc_fuzz_engine = xqc_engine_create(XQC_ENGINE_CLIENT, &config, &ssl_config,
                                        &callbacks, &transport_cbs, NULL);
    if (xqc_fuzz_engine == NULL) {
        abort();
    }

    memset(&app_cbs, 0, sizeof(app_cbs));
    xqc_engine_register_alpn(xqc_fuzz_engine, "transport", 9, &app_cbs, NULL);

    /* the extensions whose frames the parsers read with local settings */
    memset(&settings, 0, sizeof(settings));
    settings.proto_version = XQC_VERSION_V1;
    settings.enable_multipath = 1;
    settings.max_datagram_frame_size = 65535;
    settings.extended_ack_features = 2;
    settings.max_receive_timestamps_per_ack = 63;
    settings.receive_timestamps_exponent = 3;

    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));
    cid = xqc_connect(xqc_fuzz_engine, &settings, NULL, 0, "", 0,
                      &conn_ssl_config, NULL, 0, "transport", NULL);
    if (cid == NULL) {
        abort();
    }

    xqc_fuzz_conn = xqc_engine_conns_hash_find(xqc_fuzz_engine, cid, 's');
    if (xqc_fuzz_conn == NULL) {
        abort();
    }

    return 0;
}

static xqc_int_t
xqc_fuzz_parse_frame(xqc_packet_in_t *packet_in, uint64_t frame_type)
{
    xqc_connection_t *conn = xqc_fuzz_conn;
    xqc_ack_info_t ack_info;
    xqc_ack_timestamp_info_t ack_ts_info;
    xqc_stream_frame_t stream_frame;
    xqc_stream_id_t stream_id;
    xqc_cid_t cid;
    unsigned char token[XQC_MAX_TOKEN_LEN];
    unsigned char path_data[XQC_PATH_CHALLENGE_DATA_LEN];
    unsigned char *buf;
    unsigned token_len;
    uint64_t a, b, c, d;
    int bidi;
    size_t size;
    xqc_int_t ret;

    memset(&ack_info, 0, sizeof(ack_info));
    memset(&ack_ts_info, 0, sizeof(ack_ts_info));
    memset(&stream_frame, 0, sizeof(stream_frame));

    switch (frame_type) {
    case 0x00:
        return xqc_parse_padding_frame(packet_in, conn);
    case 0x01:
        return xqc_parse_ping_frame(packet_in, conn);
    case 0x02:
    case 0x03:
        return xqc_parse_ack_frame(packet_in, conn, &ack_info);
    case XQC_FRAME_TYPE_RESET_STREAM:
        return xqc_parse_reset_stream_frame(packet_in, &stream_id, &a, &b,
                                            conn);
    case XQC_FRAME_TYPE_RESET_STREAM_AT:
        return xqc_parse_reset_stream_at_frame(packet_in, &stream_id, &a, &b,
                                               &c);
    case 0x05:
        return xqc_parse_stop_sending_frame(packet_in, &stream_id, &a, conn);
    case 0x06:
        ret = xqc_parse_crypto_frame(packet_in, conn, &stream_frame);
        xqc_free(stream_frame.data);
        return ret;
    case 0x07:
        token_len = sizeof(token);
        return xqc_parse_new_token_frame(packet_in, token, &token_len, conn);
    case 0x08:
    case 0x09:
    case 0x0a:
    case 0x0b:
    case 0x0c:
    case 0x0d:
    case 0x0e:
    case 0x0f:
        ret = xqc_parse_stream_frame(packet_in, conn, &stream_frame,
                                     &stream_id);
        xqc_free(stream_frame.data);
        return ret;
    case 0x10:
        return xqc_parse_max_data_frame(packet_in, &a, conn);
    case 0x11:
        return xqc_parse_max_stream_data_frame(packet_in, &stream_id, &a, conn);
    case 0x12:
    case 0x13:
        return xqc_parse_max_streams_frame(packet_in, &a, &bidi, conn);
    case 0x14:
        return xqc_parse_data_blocked_frame(packet_in, &a, conn);
    case 0x15:
        return xqc_parse_stream_data_blocked_frame(packet_in, &stream_id, &a,
                                                   conn);
    case 0x16:
    case 0x17:
        return xqc_parse_streams_blocked_frame(packet_in, &a, &bidi, conn);
    case 0x18:
        return xqc_parse_new_conn_id_frame(packet_in, &cid, &a, conn);
    case 0x19:
        return xqc_parse_retire_conn_id_frame(packet_in, &a);
    case 0x1a:
        return xqc_parse_path_challenge_frame(packet_in, path_data);
    case 0x1b:
        return xqc_parse_path_response_frame(packet_in, path_data);
    case 0x1c:
    case 0x1d:
        return xqc_parse_conn_close_frame(packet_in, &a, conn);
    case 0x1e:
        return xqc_parse_handshake_done_frame(packet_in, conn);
    case 0x30:
    case 0x31:
        return xqc_parse_datagram_frame(packet_in, conn, &buf, &size);
    case XQC_TRANS_FRAME_TYPE_ACK_EXT:
        return xqc_parse_ack_ext_frame(packet_in, conn, &ack_info,
                                       &ack_ts_info);
    case XQC_TRANS_FRAME_TYPE_MP_ACK0:
    case XQC_TRANS_FRAME_TYPE_MP_ACK1:
        return xqc_parse_ack_mp_frame(packet_in, conn, &a, &ack_info);
    case XQC_TRANS_FRAME_TYPE_MP_ABANDON:
        return xqc_parse_path_abandon_frame(packet_in, &a, &b);
    case XQC_TRANS_FRAME_TYPE_MP_STANDBY:
    case XQC_TRANS_FRAME_TYPE_MP_AVAILABLE:
    case XQC_TRANS_FRAME_TYPE_MP_FROZEN:
        return xqc_parse_path_status_frame(packet_in, &a, &b, &c);
    case XQC_TRANS_FRAME_TYPE_MP_NEW_CONN_ID:
        return xqc_parse_mp_new_conn_id_frame(packet_in, &cid, &a, &d, conn);
    case XQC_TRANS_FRAME_TYPE_MP_RETIRE_CONN_ID:
        return xqc_parse_mp_retire_conn_id_frame(packet_in, &a, &b);
    case XQC_TRANS_FRAME_TYPE_MAX_PATH_ID:
        return xqc_parse_max_path_id_frame(packet_in, &a);
    default:
        return -XQC_EIGNORE_PKT;
    }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    xqc_packet_in_t packet_in;
    unsigned char *buf, *last_pos;
    uint64_t frame_type;

    /* a heap copy, so that ASan catches reads past the payload */
    buf = malloc(size ? size : 1);
    if (buf == NULL) {
        return 0;
    }
    memcpy(buf, data, size);

    memset(&packet_in, 0, sizeof(packet_in));
    packet_in.pi_pkt.pkt_type = XQC_PTYPE_SHORT_HEADER;
    packet_in.pi_pkt.pkt_pns = XQC_PNS_APP_DATA;
    packet_in.pos = buf;
    packet_in.last = buf + size;

    while (packet_in.pos < packet_in.last) {
        if (xqc_vint_read(packet_in.pos, packet_in.last, &frame_type) < 0) {
            break;
        }

        last_pos = packet_in.pos;
        if (xqc_fuzz_parse_frame(&packet_in, frame_type) != XQC_OK
            || packet_in.pos == last_pos)
        {
            break;
        }

        /* a parser must not consume more than the payload */
        if (packet_in.pos > packet_in.last) {
            abort();
        }
    }

    free(buf);
    return 0;
}
