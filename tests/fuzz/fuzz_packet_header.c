/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 *
 * Fuzz target: the packet headers that an endpoint parses before it can
 * remove packet protection (RFC 9000 Section 17).
 *
 * The rest of the input after the first byte is one UDP datagram. With the
 * low bit of the first byte clear, it goes to a new server engine: a
 * version negotiation, a stateless reset, a new connection from an
 * Initial, coalesced packets. With the low bit set, it goes to a client
 * connection that has sent its first Initial with the source connection ID
 * 5c5c5c5c5c5c5c5c to the destination 0dc10dc10dc10dc1: a Version
 * Negotiation, a Retry, the server's first packets. On request, the
 * harness writes that connection ID into the datagram (bit 1) and gives a
 * Retry its valid integrity tag (bit 2).
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_packet.h"
#include "xqc_fuzz_common.h"

#define XQC_FUZZ_CID_LEN  8

/*
 * the longest Retry whose integrity tag a client checks: longer tokens or
 * connection IDs are refused first
 */
#define XQC_FUZZ_RETRY_MAX_LEN                                              \
    (7 + 2 * XQC_MAX_CID_LEN + XQC_MAX_TOKEN_LEN + XQC_RETRY_INTEGRITY_TAG_LEN)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* defined in src/transport/xqc_packet_parser.c */
xqc_int_t xqc_conn_gen_retry_integrity_tag(
    xqc_connection_t *conn, const uint8_t *odcid_buf, unsigned odcid_len,
    uint8_t *retry_buf, unsigned retry_len, uint8_t *tag_buf, size_t *tag_len);

static const uint8_t xqc_fuzz_scid[XQC_FUZZ_CID_LEN] = {
    0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
};
static const uint8_t xqc_fuzz_dcid[XQC_FUZZ_CID_LEN] = {
    0x0d, 0xc1, 0x0d, 0xc1, 0x0d, 0xc1, 0x0d, 0xc1,
};


static ssize_t
xqc_fuzz_write_socket(const unsigned char *buf, size_t size,
                      const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                      void *user_data)
{
    return (ssize_t)size;
}

static ssize_t
xqc_fuzz_write_socket_ex(uint64_t path_id, const unsigned char *buf,
                         size_t size, const struct sockaddr *peer_addr,
                         socklen_t peer_addrlen, void *user_data)
{
    return (ssize_t)size;
}

static ssize_t
xqc_fuzz_stateless_reset(const unsigned char *buf, size_t size,
                         const struct sockaddr *peer_addr,
                         socklen_t peer_addrlen,
                         const struct sockaddr *local_addr,
                         socklen_t local_addrlen, void *user_data)
{
    return (ssize_t)size;
}

static int
xqc_fuzz_server_accept(xqc_engine_t *engine, xqc_connection_t *conn,
                       const xqc_cid_t *cid, void *user_data)
{
    return 0;
}

static void
xqc_fuzz_server_refuse(xqc_engine_t *engine, xqc_connection_t *conn,
                       const xqc_cid_t *cid, void *user_data)
{
}

static xqc_engine_t *
xqc_fuzz_engine(xqc_engine_type_t type)
{
    xqc_engine_ssl_config_t ssl_config;
    xqc_engine_callback_t callbacks;
    xqc_transport_callbacks_t tcbs;
    xqc_app_proto_callbacks_t app_cbs;
    xqc_config_t config;
    xqc_engine_t *engine;

    xqc_fuzz_ssl_config(&ssl_config);
    xqc_fuzz_engine_callbacks(&callbacks);
    memset(&tcbs, 0, sizeof(tcbs));
    tcbs.write_socket = xqc_fuzz_write_socket;
    tcbs.write_socket_ex = xqc_fuzz_write_socket_ex;
    tcbs.stateless_reset = xqc_fuzz_stateless_reset;
    tcbs.server_accept = xqc_fuzz_server_accept;
    tcbs.server_refuse = xqc_fuzz_server_refuse;
    tcbs.conn_send_packet_before_accept = xqc_fuzz_write_socket;

    xqc_fuzz_engine_config(&config, type);

    engine = xqc_engine_create(type, &config, &ssl_config, &callbacks, &tcbs,
                               NULL);
    if (engine == NULL) {
        abort();
    }

    memset(&app_cbs, 0, sizeof(app_cbs));
    xqc_engine_register_alpn(engine, "transport", 9, &app_cbs, NULL);
    return engine;
}

static xqc_connection_t *
xqc_fuzz_client_conn(xqc_engine_t *engine, const struct sockaddr_in *server)
{
    xqc_conn_settings_t settings;
    xqc_conn_ssl_config_t ssl_config;
    const xqc_cid_t *cid;

    memset(&settings, 0, sizeof(settings));
    settings.proto_version = XQC_VERSION_V1;
    settings.specify_client_scid = 1;
    memcpy(settings.client_scid, xqc_fuzz_scid, XQC_FUZZ_CID_LEN);
    settings.specify_client_dcid = 1;
    memcpy(settings.client_dcid, xqc_fuzz_dcid, XQC_FUZZ_CID_LEN);

    memset(&ssl_config, 0, sizeof(ssl_config));
    cid = xqc_connect(engine, &settings, NULL, 0, "test.xquic.com", 0,
                      &ssl_config, (const struct sockaddr *)server,
                      sizeof(*server), "transport", NULL);
    if (cid == NULL) {
        return NULL;
    }

    return xqc_engine_conns_hash_find(engine, cid, 's');
}

/* write the client's connection ID where the header has a DCID */
static void
xqc_fuzz_patch_dcid(uint8_t *buf, size_t len)
{
    if (len > 0 && (buf[0] & 0x80) == 0) {
        if (len >= 1 + XQC_FUZZ_CID_LEN) {
            memcpy(buf + 1, xqc_fuzz_scid, XQC_FUZZ_CID_LEN);
        }

    } else if (len >= 6 + XQC_FUZZ_CID_LEN) {
        buf[5] = XQC_FUZZ_CID_LEN;
        memcpy(buf + 6, xqc_fuzz_scid, XQC_FUZZ_CID_LEN);
    }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    xqc_fuzz_input_t in = {data, size};
    struct sockaddr_in client, server;
    xqc_connection_t *conn = NULL;
    xqc_engine_t *engine;
    const uint8_t *body;
    uint8_t *buf;
    uint8_t mode, tag[XQC_RETRY_INTEGRITY_TAG_LEN];
    size_t len, tag_len = 0;

    xqc_fuzz_now = XQC_FUZZ_START_TIME;
    mode = xqc_fuzz_u8(&in);
    len = xqc_fuzz_take(&in, in.size, &body);

    memset(&client, 0, sizeof(client));
    client.sin_family = AF_INET;
    client.sin_addr.s_addr = htonl(0x0a000002);
    client.sin_port = htons(50000);
    server = client;
    server.sin_addr.s_addr = htonl(0x0a000001);
    server.sin_port = htons(4433);

    /* a heap copy of the exact size, so that ASan catches overreads */
    buf = malloc(len ? len : 1);
    if (buf == NULL) {
        return 0;
    }
    memcpy(buf, body, len);

    if (mode & 0x01) {
        engine = xqc_fuzz_engine(XQC_ENGINE_CLIENT);
        conn = xqc_fuzz_client_conn(engine, &server);
        if (conn == NULL) {
            goto end;
        }

        if (mode & 0x02) {
            xqc_fuzz_patch_dcid(buf, len);
        }

        if ((mode & 0x04) && len > XQC_RETRY_INTEGRITY_TAG_LEN
            && len <= XQC_FUZZ_RETRY_MAX_LEN && (buf[0] & 0xf0) == 0xf0
            && xqc_conn_gen_retry_integrity_tag(
                   conn, xqc_fuzz_dcid, XQC_FUZZ_CID_LEN, buf,
                   len - XQC_RETRY_INTEGRITY_TAG_LEN, tag, &tag_len)
                   == XQC_OK
            && tag_len == XQC_RETRY_INTEGRITY_TAG_LEN)
        {
            memcpy(buf + len - XQC_RETRY_INTEGRITY_TAG_LEN, tag, tag_len);
        }

        (void)xqc_engine_packet_process(engine, buf, len,
                                        (struct sockaddr *)&client,
                                        sizeof(client),
                                        (struct sockaddr *)&server,
                                        sizeof(server), xqc_fuzz_now, NULL);

    } else {
        engine = xqc_fuzz_engine(XQC_ENGINE_SERVER);
        (void)xqc_engine_packet_process(engine, buf, len,
                                        (struct sockaddr *)&server,
                                        sizeof(server),
                                        (struct sockaddr *)&client,
                                        sizeof(client), xqc_fuzz_now, NULL);
    }

    xqc_engine_finish_recv(engine);

end:
    xqc_engine_destroy(engine);
    free(buf);
    return 0;
}
