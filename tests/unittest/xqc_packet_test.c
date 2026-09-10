/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>

#include "xqc_packet_test.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_packet_parser.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/common/xqc_log.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_cid.h"
#include "xquic/xquic_typedef.h"
#include "xquic/xquic.h"
#include "src/common/xqc_str.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "xqc_common_test.h"
#include "src/transport/xqc_conn.h"


#define XQC_TEST_SHORT_HEADER_PACKET_A "\x40\xAB\x3f\x12\x0a\xcd\xef\x00\x89"
#define XQC_TEST_LONG_HEADER_PACKET_B "\xC0\x00\x00\x00\x01\x08\xAB\x3f\x12\x0a\xcd\xef\x00\x89\x08\xAB\x3f\x12\x0a\xcd\xef\x00\x89"
#define XQC_TEST_ZERO_RTT_PACKET                                         \
    "\xD0\x00\x00\x00\x01\x08\xAB\x3f\x12\x0a\xcd\xef\x00\x89" \
    "\x08\xAB\x3f\x12\x0a\xcd\xef\x00\x89\x01\x00"

#define XQC_TEST_CHECK_CID "ab3f120acdef0089"
#define XQC_TEST_COALESCED_PACKET_SIZE 1250

static size_t xqc_test_initial_token_body(unsigned char *buf,
    size_t token_len, unsigned int two_bit);
static void xqc_test_initial_token_write(xqc_conn_type_t role);


static size_t
xqc_test_initial_token_body(unsigned char *buf, size_t token_len,
    unsigned int two_bit)
{
    size_t width = xqc_vint_len(two_bit);

    xqc_vint_write(buf, token_len, two_bit, width);
    memset(buf + width, 0xa5, token_len);
    buf[width + token_len] = 1;
    buf[width + token_len + 1] = 0;
    return width + token_len + 2;
}


void
xqc_test_client_initial_zero_token(void)
{
    xqc_connection_t *conn = test_engine_connect();
    xqc_packet_in_t packet_in;
    unsigned char buf[10];
    size_t size;
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    /* RFC 9000 Sections 16 and 17.2.2 permit all encodings of zero. */
    for (unsigned int bits = 0; bits < 4; bits++) {
        size = xqc_test_initial_token_body(buf, 0, bits);
        memset(&packet_in, 0, sizeof(packet_in));
        xqc_packet_in_init(&packet_in, buf, size, NULL, 0, 0);
        ret = xqc_packet_parse_initial(conn, &packet_in);

        CU_ASSERT_EQUAL(ret, XQC_OK);
        CU_ASSERT_EQUAL(packet_in.pi_pkt.pkt_pns, XQC_PNS_INIT);
        CU_ASSERT_EQUAL(packet_in.pi_pkt.length, 1);
        CU_ASSERT_EQUAL(packet_in.pi_pkt.pkt_num_offset, size - 1);
        CU_ASSERT_PTR_EQUAL(packet_in.last, buf + size);
        CU_ASSERT_EQUAL(conn->conn_err, 0);
    }
    xqc_engine_destroy(conn->engine);
}


void
xqc_test_client_initial_nonzero_token(void)
{
    xqc_connection_t *conn = test_engine_connect();
    const size_t lengths[] = {1, 63, 64, XQC_MAX_TOKEN_LEN};
    xqc_packet_in_t packet_in;
    unsigned char buf[XQC_MAX_TOKEN_LEN + 10];
    size_t size;
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    conn->conn_token[0] = 0x7b;
    conn->conn_token_len = 1;

    /* RFC 9000 Section 17.2.2 requires discard or PROTOCOL_VIOLATION. */
    for (unsigned int bits = 0; bits < 4; bits++) {
        for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
            if (bits < xqc_vint_get_2bit(lengths[i])) {
                continue;
            }
            size = xqc_test_initial_token_body(buf, lengths[i], bits);
            memset(&packet_in, 0, sizeof(packet_in));
            xqc_packet_in_init(&packet_in, buf, size, NULL, 0, 0);
            ret = xqc_packet_parse_initial(conn, &packet_in);

            CU_ASSERT_EQUAL(ret, -XQC_EILLPKT);
            CU_ASSERT_EQUAL(conn->conn_err, 0);
            CU_ASSERT_EQUAL(conn->conn_token_len, 1);
            CU_ASSERT_EQUAL(conn->conn_token[0], 0x7b);
            CU_ASSERT_EQUAL(packet_in.pi_pkt.pkt_num_offset, 0);
        }
    }
    xqc_engine_destroy(conn->engine);
}


void
xqc_test_server_initial_token(void)
{
    xqc_connection_t *conn = test_engine_connect();
    const size_t lengths[] = {0, 1, 63, 64, XQC_MAX_TOKEN_LEN};
    xqc_packet_in_t packet_in;
    unsigned char buf[XQC_MAX_TOKEN_LEN + 10];
    size_t size;
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    conn->conn_type = XQC_CONN_TYPE_SERVER;
    for (unsigned int bits = 0; bits < 4; bits++) {
        for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
            if (bits < xqc_vint_get_2bit(lengths[i])) {
                continue;
            }
            size = xqc_test_initial_token_body(buf, lengths[i], bits);
            memset(&packet_in, 0, sizeof(packet_in));
            xqc_packet_in_init(&packet_in, buf, size, NULL, 0, 0);
            packet_in.datagram_size = XQC_PACKET_INITIAL_MIN_LENGTH;
            ret = xqc_packet_parse_initial(conn, &packet_in);

            CU_ASSERT_EQUAL(ret, XQC_OK);
            CU_ASSERT_EQUAL(conn->conn_token_len, lengths[i]);
            CU_ASSERT_EQUAL(memcmp(conn->conn_token,
                                   buf + xqc_vint_len(bits), lengths[i]), 0);
            CU_ASSERT_EQUAL(packet_in.pi_pkt.pkt_num_offset, size - 1);
            CU_ASSERT_EQUAL(conn->conn_err, 0);
        }
    }
    conn->conn_type = XQC_CONN_TYPE_CLIENT;
    xqc_engine_destroy(conn->engine);
}


void
xqc_test_initial_token_bounds(void)
{
    xqc_connection_t *conn = test_engine_connect();
    xqc_conn_type_t roles[] = {XQC_CONN_TYPE_CLIENT, XQC_CONN_TYPE_SERVER};
    const struct {
        size_t token_len;
        unsigned int bits;
        size_t truncated_bytes;
    } cases[] = {
        {7, 0, 3},                         /* truncated token */
        {XQC_MAX_TOKEN_LEN + 1, 1, 0},      /* oversized token */
        {0, 0, 2},                         /* missing Length */
        {0, 0, 1},                         /* missing payload */
    };
    xqc_packet_in_t packet_in;
    unsigned char buf[XQC_MAX_TOKEN_LEN + 11];
    size_t size;
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    for (size_t role = 0; role < sizeof(roles) / sizeof(roles[0]); role++) {
        conn->conn_type = roles[role];
        for (unsigned int bits = 0; bits < 4; bits++) {
            xqc_test_initial_token_body(buf, 0, bits);
            size = xqc_vint_len(bits) - 1;
            memset(&packet_in, 0, sizeof(packet_in));
            xqc_packet_in_init(&packet_in, buf, size, NULL, 0, 0);
            packet_in.datagram_size = XQC_PACKET_INITIAL_MIN_LENGTH;
            ret = xqc_packet_parse_initial(conn, &packet_in);
            CU_ASSERT_EQUAL(ret, -XQC_EILLPKT);
        }

        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            size = xqc_test_initial_token_body(buf, cases[i].token_len,
                                               cases[i].bits)
                   - cases[i].truncated_bytes;
            memset(&packet_in, 0, sizeof(packet_in));
            xqc_packet_in_init(&packet_in, buf, size, NULL, 0, 0);
            packet_in.datagram_size = XQC_PACKET_INITIAL_MIN_LENGTH;
            ret = xqc_packet_parse_initial(conn, &packet_in);
            CU_ASSERT_EQUAL(ret, -XQC_EILLPKT);
            CU_ASSERT_EQUAL(conn->conn_err, 0);
        }
    }
    conn->conn_type = XQC_CONN_TYPE_CLIENT;
    xqc_engine_destroy(conn->engine);
}


static void
xqc_test_initial_token_write(xqc_conn_type_t role)
{
    xqc_connection_t *conn = test_engine_connect();
    const uint32_t lengths[] = {0, 1, 64, XQC_MAX_TOKEN_LEN};
    unsigned char token[XQC_MAX_TOKEN_LEN];
    xqc_packet_out_t *packet_out;
    unsigned char *pos;
    unsigned char *end;
    uint64_t token_len;
    size_t expected_len;
    int width;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    conn->conn_type = role;
    for (size_t i = 0; i < sizeof(token); i++) {
        token[i] = (unsigned char)i;
    }
    memcpy(conn->conn_token, token, sizeof(token));

    /* RFC 9000 Section 17.2.2 forbids echoing a client's Initial token. */
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        conn->conn_token_len = lengths[i];
        expected_len = role == XQC_CONN_TYPE_CLIENT ? lengths[i] : 0;
        packet_out = xqc_write_new_packet(conn, XQC_PTYPE_INIT);
        CU_ASSERT_PTR_NOT_NULL(packet_out);
        if (packet_out == NULL) {
            break;
        }

        pos = packet_out->po_buf + XQC_PACKET_LONG_HEADER_PREFIX_LENGTH
              + 1 + conn->dcid_set.current_dcid.cid_len
              + 1 + conn->scid_set.user_scid.cid_len;
        end = packet_out->po_buf + packet_out->po_used_size;
        width = xqc_vint_read(pos, end, &token_len);
        CU_ASSERT(width > 0);
        if (width <= 0) {
            continue;
        }

        CU_ASSERT_EQUAL(token_len, expected_len);
        CU_ASSERT_PTR_EQUAL(packet_out->po_ppktno,
                            pos + width + expected_len
                            + XQC_LONG_HEADER_LENGTH_BYTE);
        CU_ASSERT((size_t)(end - pos) >= width + expected_len);
        if ((size_t)(end - pos) >= width + expected_len) {
            CU_ASSERT_EQUAL(memcmp(pos + width, token, expected_len), 0);
        }
        CU_ASSERT_EQUAL(conn->conn_token_len, lengths[i]);
        CU_ASSERT_EQUAL(memcmp(conn->conn_token, token, sizeof(token)), 0);
    }

    conn->conn_type = XQC_CONN_TYPE_CLIENT;
    xqc_engine_destroy(conn->engine);
}


void
xqc_test_client_initial_sends_token(void)
{
    xqc_test_initial_token_write(XQC_CONN_TYPE_CLIENT);
}


void
xqc_test_server_initial_omits_token(void)
{
    xqc_test_initial_token_write(XQC_CONN_TYPE_SERVER);
}


void
xqc_test_packet_parse_cid(unsigned char *buf, size_t size, int is_short)
{
    unsigned char dcid_buf[XQC_MAX_CID_LEN * 2];
    unsigned char scid_buf[XQC_MAX_CID_LEN * 2];

    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT(engine != NULL);

    xqc_cid_t dcid, scid;
    xqc_cid_init_zero(&dcid);
    xqc_cid_init_zero(&scid);

    xqc_int_t rc = xqc_packet_parse_cid(&dcid, &scid, engine->config->cid_len, buf, size);
    CU_ASSERT(rc == XQC_OK);

    xqc_hex_dump(dcid_buf, dcid.cid_buf, dcid.cid_len);
    xqc_hex_dump(scid_buf, scid.cid_buf, scid.cid_len);

    CU_ASSERT(((size_t)dcid.cid_len * 2) == (sizeof(XQC_TEST_CHECK_CID)-1));
    CU_ASSERT(memcmp((unsigned char *)XQC_TEST_CHECK_CID, dcid_buf, ((size_t)dcid.cid_len * 2)) == 0);

    if (!is_short) {
        CU_ASSERT(((size_t)scid.cid_len * 2) == (sizeof(XQC_TEST_CHECK_CID)-1));
        CU_ASSERT(memcmp((unsigned char *)XQC_TEST_CHECK_CID, scid_buf, ((size_t)scid.cid_len * 2)) == 0);
    }

    xqc_engine_destroy(engine);
}

void
xqc_test_short_header_packet_parse_cid()
{
    xqc_test_packet_parse_cid((unsigned char *)XQC_TEST_SHORT_HEADER_PACKET_A,
                              sizeof(XQC_TEST_SHORT_HEADER_PACKET_A)-1, 1);
}

void
xqc_test_long_header_packet_parse_cid()
{
    xqc_test_packet_parse_cid((unsigned char *)XQC_TEST_LONG_HEADER_PACKET_B,
                              sizeof(XQC_TEST_LONG_HEADER_PACKET_B)-1, 0);
}


void
xqc_test_client_discards_received_zero_rtt(void)
{
    xqc_connection_t *conn = test_engine_connect();
    xqc_packet_in_t packet_in;
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    CU_ASSERT_EQUAL_FATAL(conn->conn_type, XQC_CONN_TYPE_CLIENT);

    xqc_packet_in_init(&packet_in,
                       (unsigned char *)XQC_TEST_ZERO_RTT_PACKET,
                       sizeof(XQC_TEST_ZERO_RTT_PACKET) - 1, NULL, 0, 0);

    ret = xqc_packet_process_single(conn, &packet_in, NULL, NULL);

    /*
     * RFC 9001 Section 5.6 requires discard before decryption. The receive
     * path must not retain the packet or mark client-side 0-RTT state.
     */
    CU_ASSERT_EQUAL(ret, -XQC_EIGNORE_PKT);
    CU_ASSERT_EQUAL(conn->undecrypt_count[XQC_ENC_LEV_0RTT], 0);
    CU_ASSERT_FALSE(conn->conn_flag & XQC_CONN_FLAG_HAS_0RTT);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_server_buffers_received_zero_rtt(void)
{
    xqc_connection_t *conn = test_engine_connect();
    xqc_packet_in_t packet_in;
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    conn->conn_type = XQC_CONN_TYPE_SERVER;

    xqc_packet_in_init(&packet_in,
                       (unsigned char *)XQC_TEST_ZERO_RTT_PACKET,
                       sizeof(XQC_TEST_ZERO_RTT_PACKET) - 1, NULL, 0, 0);

    ret = xqc_packet_process_single(conn, &packet_in, NULL, NULL);

    CU_ASSERT_EQUAL(ret, -XQC_EWAITING);
    CU_ASSERT_EQUAL(conn->undecrypt_count[XQC_ENC_LEV_0RTT], 1);
    CU_ASSERT_TRUE(conn->conn_flag & XQC_CONN_FLAG_HAS_0RTT);

    conn->conn_type = XQC_CONN_TYPE_CLIENT;
    xqc_engine_destroy(conn->engine);
}


void
xqc_test_packet_out_remained_size(void)
{
    xqc_packet_out_t *packet_out;

    packet_out = xqc_packet_out_create(16);
    CU_ASSERT_PTR_NOT_NULL_FATAL(packet_out);

    CU_ASSERT_EQUAL(xqc_get_po_remained_size(packet_out), 16);

    packet_out->po_used_size = 4;
    packet_out->po_reserved_size = 3;
    CU_ASSERT_EQUAL(xqc_get_po_remained_size(packet_out), 9);

    packet_out->po_used_size = 17;
    packet_out->po_reserved_size = 0;
    CU_ASSERT_EQUAL(xqc_get_po_remained_size(packet_out), 0);

    packet_out->po_used_size = 15;
    packet_out->po_reserved_size = 2;
    CU_ASSERT_EQUAL(xqc_get_po_remained_size(packet_out), 0);

    xqc_packet_out_destroy(packet_out);
}





extern xqc_usec_t xqc_now();



typedef struct test_ctx {
    xqc_engine_t        *engine;
    xqc_connection_t    *c;
    xqc_cid_t            cid;
    char                 buf[2048];
    size_t               buf_len;
} test_ctx;

static size_t xqc_test_build_initial_token(test_ctx *sender,
    const xqc_cid_t *dcid, xqc_packet_number_t packet_number,
    xqc_bool_t connection_close, const unsigned char *token,
    uint32_t token_len, size_t packet_size, unsigned char *buf,
    size_t buf_cap);
static size_t xqc_test_build_initial(test_ctx *cli, const xqc_cid_t *dcid,
    xqc_packet_number_t packet_number, xqc_bool_t connection_close,
    size_t packet_size, unsigned char *buf, size_t buf_cap);


ssize_t
xqc_test_server_write(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *conn_user_data)
{
    test_ctx *tctx = (test_ctx *)conn_user_data;
    memcpy(tctx->buf, buf, size);
    tctx->buf_len = size;

    return size;
}

int
xqc_test_server_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *user_data, void *conn_proto_data)
{
    test_ctx *tctx = (test_ctx *)user_data;
    tctx->c = conn;
    memcpy(&tctx->cid, cid, sizeof(xqc_cid_t));

    xqc_conn_set_alp_user_data(conn, tctx);

    return 0;
}

ssize_t
xqc_test_client_write(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *conn_user_data)
{
    test_ctx *tctx = (test_ctx *)conn_user_data;
    memcpy(tctx->buf, buf, size);
    tctx->buf_len = size;

    return size;
}

int
xqc_test_client_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *user_data, void *conn_proto_data)
{
    test_ctx *tctx = (test_ctx *)user_data;
    tctx->c = conn;
    memcpy(&tctx->cid, cid, sizeof(xqc_cid_t));

    xqc_conn_set_alp_user_data(conn, tctx);

    return 0;
}

void
xqc_test_set_event_timer(xqc_msec_t wake_after, void *engine_user_data)
{
    return;
}

xqc_engine_t *
test_create_engine_buf_server(test_ctx *tctx)
{
    xqc_engine_ssl_config_t  engine_ssl_config;
    engine_ssl_config.private_key_file = "./server.key";
    engine_ssl_config.cert_file = "./server.crt";
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;
    engine_ssl_config.session_ticket_key_len = 0;
    engine_ssl_config.session_ticket_key_data = NULL;

    xqc_engine_callback_t callback = {
        .set_event_timer = xqc_test_set_event_timer,
    };

    xqc_transport_callbacks_t tcbs = {
        .write_socket = xqc_test_server_write,
    };

    xqc_app_proto_callbacks_t transport_cbs = {
        .conn_cbs.conn_create_notify = xqc_test_server_conn_create_notify,
    };

    xqc_conn_settings_t conn_settings;
    xqc_engine_t *engine = xqc_engine_create(XQC_ENGINE_SERVER, NULL, &engine_ssl_config,
                                             &callback, &tcbs, tctx);
    if (engine == NULL) {
        return NULL;
    }

    /* transport ALPN */
    xqc_engine_register_alpn(engine, "transport", 9, &transport_cbs, NULL);

    return engine;
}



xqc_engine_t *
test_create_engine_buf_client(test_ctx *tctx)
{
    xqc_engine_ssl_config_t  engine_ssl_config;
    engine_ssl_config.private_key_file = "./server.key";
    engine_ssl_config.cert_file = "./server.crt";
    engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_TLS_GROUPS;
    engine_ssl_config.session_ticket_key_len = 0;
    engine_ssl_config.session_ticket_key_data = NULL;

    xqc_engine_callback_t callback = {
        .set_event_timer = xqc_test_set_event_timer,
    };

    xqc_transport_callbacks_t tcbs = {
        .write_socket = xqc_test_client_write,
    };

    xqc_app_proto_callbacks_t transport_cbs = {
        .conn_cbs.conn_create_notify = xqc_test_client_conn_create_notify,
    };

    xqc_conn_settings_t conn_settings;
    xqc_engine_t *engine = xqc_engine_create(XQC_ENGINE_CLIENT, NULL, &engine_ssl_config,
                                             &callback, &tcbs, tctx);
    if (engine == NULL) {
        return NULL;
    }

    /* transport ALPN */
    xqc_engine_register_alpn(engine, "transport", 9, &transport_cbs, NULL);

    return engine;
}


void
xqc_test_packet_encrypt_hp_sample_boundary()
{
    test_ctx         svr_tctx   = {0};
    test_ctx         cli_tctx   = {0};

    svr_tctx.engine = test_create_engine_buf_server(&svr_tctx);
    cli_tctx.engine = test_create_engine_buf_client(&cli_tctx);

    xqc_conn_settings_t conn_settings;
    memset(&conn_settings, 0, sizeof(xqc_conn_settings_t));
    conn_settings.proto_version = XQC_VERSION_V1;
    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));

    xqc_connect(cli_tctx.engine, &conn_settings, NULL, 0, "", 0,
                &conn_ssl_config, NULL, 0, "transport", &cli_tctx);

    struct sockaddr_in6 peer_addr;
    socklen_t peer_addrlen = sizeof(peer_addr);

    struct sockaddr_in6 local_addr;
    socklen_t local_addrlen = sizeof(local_addr);

    xqc_engine_packet_process(svr_tctx.engine, cli_tctx.buf, cli_tctx.buf_len,
                              (struct sockaddr *)&local_addr, local_addrlen,
                              (struct sockaddr *)&peer_addr, peer_addrlen, xqc_now(), &svr_tctx);

    xqc_packet_out_t *po = xqc_packet_out_create(2048);
    CU_ASSERT(po != NULL);

    memcpy(po->po_pkt.pkt_scid.cid_buf, cli_tctx.c->scid_set.user_scid.cid_buf,
           cli_tctx.c->scid_set.user_scid.cid_len);
    po->po_pkt.pkt_scid.cid_len = cli_tctx.c->scid_set.user_scid.cid_len;

    memcpy(po->po_pkt.pkt_dcid.cid_buf, cli_tctx.c->dcid_set.current_dcid.cid_buf,
            cli_tctx.c->dcid_set.current_dcid.cid_len);
    po->po_pkt.pkt_dcid.cid_len = cli_tctx.c->dcid_set.current_dcid.cid_len;

    ssize_t po_size = xqc_gen_long_packet_header(
        po, po->po_pkt.pkt_dcid.cid_buf, po->po_pkt.pkt_dcid.cid_len,
        po->po_pkt.pkt_scid.cid_buf, po->po_pkt.pkt_scid.cid_len,
        NULL, 0, XQC_VERSION_V1, XQC_PKTNO_BITS);
    CU_ASSERT(po_size > 0);
    po->po_used_size += po_size;

    uint8_t enc_buf[2048];
    size_t enc_len = 0;
    xqc_int_t ret = xqc_packet_encrypt_buf(cli_tctx.c, po, enc_buf, sizeof(enc_buf), &enc_len);
    CU_ASSERT(ret == XQC_OK);

    xqc_packet_out_destroy(po);
    xqc_conn_close(cli_tctx.engine, &cli_tctx.cid);
    xqc_engine_destroy(cli_tctx.engine);

    xqc_conn_close(svr_tctx.engine, &svr_tctx.cid);
    xqc_engine_destroy(svr_tctx.engine);
}


void
xqc_test_empty_pkt()
{
    test_ctx         svr_tctx   = {0};
    test_ctx         cli_tctx   = {0};
    xqc_packet_out_t *po        = NULL;

    svr_tctx.engine = test_create_engine_buf_server(&svr_tctx);
    cli_tctx.engine = test_create_engine_buf_client(&cli_tctx);

    CU_ASSERT(svr_tctx.engine != NULL);
    CU_ASSERT(cli_tctx.engine != NULL);
    if (svr_tctx.engine == NULL || cli_tctx.engine == NULL) {
        goto finish;
    }

    xqc_conn_settings_t conn_settings;
    memset(&conn_settings, 0, sizeof(xqc_conn_settings_t));
    conn_settings.proto_version = XQC_VERSION_V1;
    xqc_conn_ssl_config_t conn_ssl_config;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));

    /* create client instance, will trigger create_notiry and write_socket */
    const xqc_cid_t *cid = xqc_connect(cli_tctx.engine, &conn_settings,
                                       NULL, 0, "", 0, &conn_ssl_config,
                                       NULL, 0, "transport", &cli_tctx);
    CU_ASSERT(cid != NULL);
    CU_ASSERT(cli_tctx.c != NULL);
    if (cid == NULL || cli_tctx.c == NULL) {
        goto finish;
    }

    struct sockaddr_in6 peer_addr;
    socklen_t peer_addrlen = sizeof(peer_addr);

    struct sockaddr_in6 local_addr;
    socklen_t local_addrlen = sizeof(local_addr);

    /* server will process the initial packet and get the secret of initial pns */
    xqc_engine_packet_process(svr_tctx.engine, cli_tctx.buf, cli_tctx.buf_len,
                              (struct sockaddr *)&local_addr, local_addrlen,
                              (struct sockaddr *)&peer_addr, peer_addrlen, xqc_now(), &svr_tctx);

    CU_ASSERT(svr_tctx.c != NULL);
    if (svr_tctx.c == NULL) {
        goto finish;
    }

    /* generate an Initial pkt with no payload */
    po = xqc_packet_out_create(2048);
    CU_ASSERT(po != NULL);
    if (po == NULL) {
        goto finish;
    }

    memcpy(po->po_pkt.pkt_scid.cid_buf, cli_tctx.c->scid_set.user_scid.cid_buf,
           cli_tctx.c->scid_set.user_scid.cid_len);
    po->po_pkt.pkt_scid.cid_len = cli_tctx.c->scid_set.user_scid.cid_len;

    memcpy(po->po_pkt.pkt_dcid.cid_buf, cli_tctx.c->dcid_set.current_dcid.cid_buf,
            cli_tctx.c->dcid_set.current_dcid.cid_len);
    po->po_pkt.pkt_dcid.cid_len = cli_tctx.c->dcid_set.current_dcid.cid_len;

    ssize_t po_size = xqc_gen_long_packet_header(
        po, po->po_pkt.pkt_dcid.cid_buf, po->po_pkt.pkt_dcid.cid_len,
        po->po_pkt.pkt_scid.cid_buf, po->po_pkt.pkt_scid.cid_len,
        NULL, 0, XQC_VERSION_V1, XQC_PKTNO_BITS);
    CU_ASSERT(po_size > 0);
    po->po_used_size += po_size;

    /* client encrypt the Initial pkt */
    xqc_int_t ret = xqc_packet_encrypt(cli_tctx.c, po);
    CU_ASSERT(ret == XQC_OK);

    /* server decrypt the Initial pkt */
    ret = xqc_conn_process_packet(svr_tctx.c, cli_tctx.c->enc_pkt,
                                  cli_tctx.c->enc_pkt_len, xqc_now());
    CU_ASSERT(svr_tctx.c->conn_err == TRA_PROTOCOL_VIOLATION);


finish:
    if (po != NULL) {
        xqc_packet_out_destroy(po);
    }

    if (cli_tctx.engine != NULL) {
        if (cli_tctx.c != NULL) {
            xqc_conn_close(cli_tctx.engine, &cli_tctx.cid);
        }
        xqc_engine_destroy(cli_tctx.engine);
    }

    if (svr_tctx.engine != NULL) {
        if (svr_tctx.c != NULL) {
            xqc_conn_close(svr_tctx.engine, &svr_tctx.cid);
        }
        xqc_engine_destroy(svr_tctx.engine);
    }
}


void
xqc_test_stateless_reset_parse_boundary(void)
{
    const uint8_t *sr_token = NULL;
    xqc_int_t      ret;

    /*
     * RFC 9000 §10.3: minimum Stateless Reset is 21 bytes
     * (1 byte header + 4 bytes unpredictable + 16 bytes token).
     * Build a minimal 21-byte packet: short-header bit set, random
     * filler, then a 16-byte fake token at the tail.
     */
    unsigned char pkt[64];
    memset(pkt, 0xAB, sizeof(pkt));
    pkt[0] = 0x40; /* short header: Fixed Bit = 1 */

    /* Case 1: 20 bytes — below minimum, must reject */
    sr_token = NULL;
    ret = xqc_packet_parse_stateless_reset(pkt, 20, &sr_token);
    CU_ASSERT(ret != XQC_OK);

    /* Case 2: 21 bytes — exact minimum, must accept */
    sr_token = NULL;
    ret = xqc_packet_parse_stateless_reset(pkt, 21, &sr_token);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(sr_token != NULL);
    CU_ASSERT(sr_token == pkt + 21 - XQC_STATELESS_RESET_TOKENLEN);

    /* Case 3: 22 bytes — above minimum, must accept */
    sr_token = NULL;
    ret = xqc_packet_parse_stateless_reset(pkt, 22, &sr_token);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(sr_token != NULL);
    CU_ASSERT(sr_token == pkt + 22 - XQC_STATELESS_RESET_TOKENLEN);
}


static xqc_int_t
xqc_test_coalesced_setup(test_ctx *cli, test_ctx *svr)
{
    struct sockaddr_in6 peer_addr;
    struct sockaddr_in6 local_addr;
    xqc_conn_settings_t conn_settings;
    xqc_conn_ssl_config_t conn_ssl_config;
    const xqc_cid_t *cid;

    svr->engine = test_create_engine_buf_server(svr);
    cli->engine = test_create_engine_buf_client(cli);
    if (svr->engine == NULL || cli->engine == NULL) {
        return XQC_ERROR;
    }

    memset(&conn_settings, 0, sizeof(conn_settings));
    conn_settings.proto_version = XQC_VERSION_V1;
    memset(&conn_ssl_config, 0, sizeof(conn_ssl_config));

    cid = xqc_connect(cli->engine, &conn_settings, NULL, 0, "", 0,
                      &conn_ssl_config, NULL, 0, "transport", cli);
    if (cid == NULL || cli->c == NULL) {
        return XQC_ERROR;
    }

    memset(&peer_addr, 0, sizeof(peer_addr));
    memset(&local_addr, 0, sizeof(local_addr));
    xqc_engine_packet_process(svr->engine, cli->buf, cli->buf_len,
                              (struct sockaddr *)&local_addr,
                              sizeof(local_addr),
                              (struct sockaddr *)&peer_addr,
                              sizeof(peer_addr), xqc_now(), svr);

    return svr->c == NULL ? XQC_ERROR : XQC_OK;
}


static void
xqc_test_coalesced_teardown(test_ctx *cli, test_ctx *svr)
{
    if (cli->engine != NULL) {
        if (cli->c != NULL) {
            xqc_conn_close(cli->engine, &cli->cid);
        }
        xqc_engine_destroy(cli->engine);
    }

    if (svr->engine != NULL) {
        if (svr->c != NULL) {
            xqc_conn_close(svr->engine, &svr->cid);
        }
        xqc_engine_destroy(svr->engine);
    }
}


static size_t
xqc_test_build_initial_token(test_ctx *sender, const xqc_cid_t *dcid,
    xqc_packet_number_t packet_number, xqc_bool_t connection_close,
    const unsigned char *token, uint32_t token_len, size_t packet_size,
    unsigned char *buf, size_t buf_cap)
{
    xqc_packet_out_t *packet_out;
    size_t encrypted_size = 0;
    size_t padding_size;
    ssize_t written;
    xqc_int_t ret;

    packet_out = xqc_packet_out_create(2048);
    if (packet_out == NULL) {
        return 0;
    }

    packet_out->po_pkt.pkt_type = XQC_PTYPE_INIT;
    packet_out->po_pkt.pkt_pns = XQC_PNS_INIT;
    packet_out->po_pkt.pkt_num = packet_number;
    xqc_cid_set(&packet_out->po_pkt.pkt_scid,
                sender->c->scid_set.user_scid.cid_buf,
                sender->c->scid_set.user_scid.cid_len);
    xqc_cid_set(&packet_out->po_pkt.pkt_dcid, dcid->cid_buf, dcid->cid_len);

    written = xqc_gen_long_packet_header(
        packet_out, packet_out->po_pkt.pkt_dcid.cid_buf,
        packet_out->po_pkt.pkt_dcid.cid_len,
        packet_out->po_pkt.pkt_scid.cid_buf,
        packet_out->po_pkt.pkt_scid.cid_len, token, token_len,
        XQC_VERSION_V1, XQC_PKTNO_BITS);
    if (written <= 0) {
        goto end;
    }
    packet_out->po_used_size += written;

    if (connection_close) {
        written = xqc_gen_conn_close_frame(packet_out,
                                           TRA_PROTOCOL_VIOLATION, 0, 0,
                                           NULL, 0);
        if (written <= 0) {
            goto end;
        }
        packet_out->po_used_size += written;
    }

    if (packet_out->po_used_size + XQC_TLS_AEAD_OVERHEAD_MAX_LEN
        >= packet_size)
    {
        goto end;
    }

    padding_size = packet_size
                   - packet_out->po_used_size
                   - XQC_TLS_AEAD_OVERHEAD_MAX_LEN;
    memset(packet_out->po_buf + packet_out->po_used_size, 0, padding_size);
    packet_out->po_used_size += padding_size;

    ret = xqc_packet_encrypt_buf(sender->c, packet_out, buf, buf_cap,
                                 &encrypted_size);
    if (ret != XQC_OK) {
        encrypted_size = 0;
    }

end:
    xqc_packet_out_destroy(packet_out);
    return encrypted_size;
}


static size_t
xqc_test_build_initial(test_ctx *cli, const xqc_cid_t *dcid,
    xqc_packet_number_t packet_number, xqc_bool_t connection_close,
    size_t packet_size, unsigned char *buf, size_t buf_cap)
{
    return xqc_test_build_initial_token(cli, dcid, packet_number,
                                        connection_close, NULL, 0,
                                        packet_size, buf, buf_cap);
}


void
xqc_test_initial_token_discard_recovery(void)
{
    test_ctx cli = {0};
    test_ctx svr = {0};
    unsigned char invalid[2048];
    unsigned char valid[2048];
    const unsigned char token[] = {0xa5};
    xqc_conn_state_t state;
    xqc_conn_flag_t flags;
    xqc_usec_t last_recv;
    uint64_t dropped_count;
    size_t invalid_size;
    size_t valid_size;
    int recv_index;
    xqc_int_t ret;

    ret = xqc_test_coalesced_setup(&cli, &svr);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    if (ret != XQC_OK) {
        goto end;
    }

    state = cli.c->conn_state;
    flags = cli.c->conn_flag;
    last_recv = cli.c->conn_last_recv_time;
    dropped_count = cli.c->packet_dropped_count;
    recv_index = cli.c->rcv_pkt_stats.curr_index;

    invalid_size = xqc_test_build_initial_token(
        &svr, &cli.c->scid_set.user_scid, 1, XQC_TRUE,
        token, sizeof(token), XQC_TEST_COALESCED_PACKET_SIZE,
        invalid, sizeof(invalid));
    valid_size = xqc_test_build_initial(
        &svr, &cli.c->scid_set.user_scid, 2, XQC_TRUE,
        XQC_TEST_COALESCED_PACKET_SIZE, valid, sizeof(valid));
    CU_ASSERT_NOT_EQUAL(invalid_size, 0);
    CU_ASSERT_NOT_EQUAL(valid_size, 0);
    if (invalid_size == 0 || valid_size == 0) {
        goto end;
    }

    /* RFC 9000 Section 17.2.2: discard before the close frame acts. */
    ret = xqc_conn_process_packet(cli.c, invalid, invalid_size, xqc_now());
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(cli.c->conn_err, 0);
    CU_ASSERT_EQUAL(cli.c->conn_state, state);
    CU_ASSERT_EQUAL(cli.c->conn_flag, flags);
    CU_ASSERT_EQUAL(cli.c->conn_close_recv_time, 0);
    CU_ASSERT_EQUAL(cli.c->conn_last_recv_time, last_recv);
    CU_ASSERT_EQUAL(cli.c->packet_dropped_count, dropped_count);
    CU_ASSERT_EQUAL(cli.c->rcv_pkt_stats.pkt_err[recv_index], -XQC_EILLPKT);

    ret = xqc_conn_process_packet(cli.c, valid, valid_size, xqc_now());
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_NOT_EQUAL(cli.c->conn_close_recv_time, 0);
    CU_ASSERT(cli.c->conn_state >= XQC_CONN_STATE_DRAINING);
    CU_ASSERT_EQUAL(cli.c->packet_dropped_count, dropped_count);

end:
    xqc_test_coalesced_teardown(&cli, &svr);
}


void
xqc_test_coalesced_matching_dcid_processed(void)
{
    test_ctx cli = {0};
    test_ctx svr = {0};
    unsigned char first[2048];
    unsigned char second[2048];
    unsigned char datagram[4096];
    size_t first_size;
    size_t second_size;
    xqc_int_t ret;

    ret = xqc_test_coalesced_setup(&cli, &svr);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    if (ret != XQC_OK) {
        xqc_test_coalesced_teardown(&cli, &svr);
        return;
    }

    first_size = xqc_test_build_initial(
        &cli, &cli.c->dcid_set.current_dcid, 1, XQC_FALSE,
        XQC_TEST_COALESCED_PACKET_SIZE, first, sizeof(first));
    second_size = xqc_test_build_initial(
        &cli, &cli.c->dcid_set.current_dcid, 2, XQC_TRUE,
        XQC_TEST_COALESCED_PACKET_SIZE, second, sizeof(second));
    CU_ASSERT_NOT_EQUAL(first_size, 0);
    CU_ASSERT_NOT_EQUAL(second_size, 0);
    if (first_size == 0 || second_size == 0) {
        xqc_test_coalesced_teardown(&cli, &svr);
        return;
    }

    memcpy(datagram, first, first_size);
    memcpy(datagram + first_size, second, second_size);
    ret = xqc_conn_process_packet(svr.c, datagram,
                                  first_size + second_size, xqc_now());

    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_NOT_EQUAL(svr.c->conn_close_recv_time, 0);
    CU_ASSERT(svr.c->conn_state >= XQC_CONN_STATE_DRAINING);

    xqc_test_coalesced_teardown(&cli, &svr);
}


void
xqc_test_coalesced_mismatching_dcid_ignored(void)
{
    test_ctx cli = {0};
    test_ctx svr = {0};
    xqc_cid_t matching_dcid;
    xqc_cid_t mismatching_dcid;
    unsigned char first[2048];
    unsigned char second[2048];
    unsigned char third[2048];
    unsigned char datagram[6144];
    size_t first_size;
    size_t second_size;
    size_t third_size;
    size_t offset;
    uint64_t dropped_count;
    xqc_conn_state_t state;
    xqc_int_t ret;

    ret = xqc_test_coalesced_setup(&cli, &svr);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    if (ret != XQC_OK) {
        xqc_test_coalesced_teardown(&cli, &svr);
        return;
    }

    xqc_cid_set(&matching_dcid, cli.c->dcid_set.current_dcid.cid_buf,
                cli.c->dcid_set.current_dcid.cid_len);
    xqc_cid_set(&mismatching_dcid, matching_dcid.cid_buf,
                matching_dcid.cid_len);
    mismatching_dcid.cid_buf[0] ^= 0xff;
    state = svr.c->conn_state;
    dropped_count = svr.c->packet_dropped_count;

    first_size = xqc_test_build_initial(&cli, &matching_dcid, 1,
                                        XQC_FALSE,
                                        XQC_TEST_COALESCED_PACKET_SIZE,
                                        first, sizeof(first));
    second_size = xqc_test_build_initial(&cli, &mismatching_dcid, 2,
                                         XQC_TRUE,
                                         XQC_TEST_COALESCED_PACKET_SIZE,
                                         second, sizeof(second));
    CU_ASSERT_NOT_EQUAL(first_size, 0);
    CU_ASSERT_NOT_EQUAL(second_size, 0);
    if (first_size == 0 || second_size == 0) {
        xqc_test_coalesced_teardown(&cli, &svr);
        return;
    }

    memcpy(datagram, first, first_size);
    memcpy(datagram + first_size, second, second_size);
    ret = xqc_conn_process_packet(svr.c, datagram,
                                  first_size + second_size, xqc_now());

    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(svr.c->conn_close_recv_time, 0);
    CU_ASSERT_EQUAL(svr.c->conn_state, state);
    CU_ASSERT_EQUAL(svr.c->packet_dropped_count, dropped_count);

    first_size = xqc_test_build_initial(&cli, &matching_dcid, 3,
                                        XQC_FALSE,
                                        XQC_TEST_COALESCED_PACKET_SIZE,
                                        first, sizeof(first));
    second_size = xqc_test_build_initial(&cli, &mismatching_dcid, 4,
                                         XQC_FALSE,
                                         XQC_TEST_COALESCED_PACKET_SIZE,
                                         second, sizeof(second));
    third_size = xqc_test_build_initial(&cli, &matching_dcid, 5,
                                        XQC_TRUE,
                                        XQC_TEST_COALESCED_PACKET_SIZE,
                                        third, sizeof(third));
    CU_ASSERT_NOT_EQUAL(first_size, 0);
    CU_ASSERT_NOT_EQUAL(second_size, 0);
    CU_ASSERT_NOT_EQUAL(third_size, 0);
    if (first_size == 0 || second_size == 0 || third_size == 0) {
        xqc_test_coalesced_teardown(&cli, &svr);
        return;
    }

    offset = 0;
    memcpy(datagram + offset, first, first_size);
    offset += first_size;
    memcpy(datagram + offset, second, second_size);
    offset += second_size;
    memcpy(datagram + offset, third, third_size);
    offset += third_size;

    ret = xqc_conn_process_packet(svr.c, datagram, offset, xqc_now());
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_NOT_EQUAL(svr.c->conn_close_recv_time, 0);
    CU_ASSERT(svr.c->conn_state >= XQC_CONN_STATE_DRAINING);
    CU_ASSERT_EQUAL(svr.c->packet_dropped_count, dropped_count);

    xqc_test_coalesced_teardown(&cli, &svr);
}


void
xqc_test_coalesced_initial_datagram_minimum(void)
{
    test_ctx cli = {0};
    test_ctx svr = {0};
    unsigned char first[XQC_PACKET_INITIAL_MIN_LENGTH];
    unsigned char second[XQC_PACKET_INITIAL_MIN_LENGTH];
    unsigned char datagram[XQC_PACKET_INITIAL_MIN_LENGTH];
    size_t packet_size = XQC_PACKET_INITIAL_MIN_LENGTH / 2;
    size_t first_size;
    size_t second_size;
    xqc_int_t ret;

    ret = xqc_test_coalesced_setup(&cli, &svr);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    if (ret != XQC_OK) {
        xqc_test_coalesced_teardown(&cli, &svr);
        return;
    }

    first_size = xqc_test_build_initial(
        &cli, &cli.c->dcid_set.current_dcid, 1, XQC_FALSE, packet_size,
        first, sizeof(first));
    second_size = xqc_test_build_initial(
        &cli, &cli.c->dcid_set.current_dcid, 2, XQC_TRUE, packet_size,
        second, sizeof(second));
    CU_ASSERT_EQUAL(first_size, packet_size);
    CU_ASSERT_EQUAL(second_size, packet_size);
    if (first_size != packet_size || second_size != packet_size) {
        xqc_test_coalesced_teardown(&cli, &svr);
        return;
    }

    memcpy(datagram, first, first_size);
    memcpy(datagram + first_size, second, second_size);

    /* RFC 9000 Sections 12.2 and 14.1 allow expansion by coalescing. */
    ret = xqc_conn_process_packet(svr.c, datagram, sizeof(datagram),
                                  xqc_now());

    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_NOT_EQUAL(svr.c->conn_close_recv_time, 0);
    CU_ASSERT(svr.c->conn_state >= XQC_CONN_STATE_DRAINING);

    xqc_test_coalesced_teardown(&cli, &svr);
}


void
xqc_test_coalesced_initial_datagram_too_small(void)
{
    test_ctx cli = {0};
    test_ctx svr = {0};
    unsigned char first[XQC_PACKET_INITIAL_MIN_LENGTH];
    unsigned char second[XQC_PACKET_INITIAL_MIN_LENGTH];
    unsigned char datagram[XQC_PACKET_INITIAL_MIN_LENGTH - 1];
    size_t first_packet_size = XQC_PACKET_INITIAL_MIN_LENGTH / 2;
    size_t second_packet_size = sizeof(datagram) - first_packet_size;
    size_t first_size;
    size_t second_size;
    xqc_int_t ret;

    ret = xqc_test_coalesced_setup(&cli, &svr);
    CU_ASSERT_EQUAL(ret, XQC_OK);
    if (ret != XQC_OK) {
        xqc_test_coalesced_teardown(&cli, &svr);
        return;
    }

    first_size = xqc_test_build_initial(
        &cli, &cli.c->dcid_set.current_dcid, 1, XQC_FALSE,
        first_packet_size, first, sizeof(first));
    second_size = xqc_test_build_initial(
        &cli, &cli.c->dcid_set.current_dcid, 2, XQC_TRUE,
        second_packet_size, second, sizeof(second));
    CU_ASSERT_EQUAL(first_size, first_packet_size);
    CU_ASSERT_EQUAL(second_size, second_packet_size);
    if (first_size != first_packet_size || second_size != second_packet_size) {
        xqc_test_coalesced_teardown(&cli, &svr);
        return;
    }

    memcpy(datagram, first, first_size);
    memcpy(datagram + first_size, second, second_size);

    /* RFC 9000 Section 14.1 rejects an undersized Initial datagram. */
    ret = xqc_conn_process_packet(svr.c, datagram, sizeof(datagram),
                                  xqc_now());

    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(svr.c->conn_err, TRA_PROTOCOL_VIOLATION);
    CU_ASSERT_EQUAL(svr.c->conn_close_recv_time, 0);

    xqc_test_coalesced_teardown(&cli, &svr);
}
