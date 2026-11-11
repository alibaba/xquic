/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xquic/xquic.h"
#include "src/transport/xqc_packet.h"
#include "src/common/xqc_log.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_multipath.h"
#include "xquic/xquic_typedef.h"
#include "src/common/xqc_str.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_timer.h"
#include "src/congestion_control/xqc_new_reno.h"
#include "src/transport/xqc_packet_parser.h"
#include "xqc_common_test.h"

xqc_int_t xqc_need_padding(xqc_connection_t *conn, xqc_packet_out_t *packet_out);
xqc_int_t xqc_cid_encryption_aes_128_ecb(unsigned char *plaintext,
    size_t plaintext_len, uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *key, size_t key_len, xqc_engine_t *engine);


void
xqc_test_engine_create()
{
    xqc_engine_t *engine = test_create_engine();
    CU_ASSERT(engine != NULL);
    xqc_engine_destroy(engine);
    engine = NULL;
}


#define XQC_TEST_SHORT_HEADER_PACKET_A "\x40\xAB\x3f\x12\x0a\xcd\xef\x00\x89"
#define XQC_TEST_LONG_HEADER_PACKET_B "\xC0\xFF\x00\x00\x1D\x08\xAB\x3f\x12\x0a\xcd\xef\x00\x89\x08\xAB\x3f\x12\x0a\xcd\xef\x00\x89"
#define XQC_TEST_INITIAL_FIRST_BYTE 0xC0
#define XQC_TEST_0RTT_FIRST_BYTE 0xD0

#define XQC_TEST_CHECK_CID "ab3f120acdef0089"


static void
xqc_test_build_long_header(unsigned char *packet, size_t packet_size,
    unsigned char first_byte)
{
    static const unsigned char cid[] = {0xAB, 0x3F, 0x12, 0x0A, 0xCD, 0xEF, 0x00, 0x89};

    xqc_memzero(packet, packet_size);
    packet[0] = first_byte;
    packet[4] = XQC_VERSION_V1;
    packet[5] = sizeof(cid);
    xqc_memcpy(packet + 6, cid, sizeof(cid));
    packet[14] = sizeof(cid);
    xqc_memcpy(packet + 15, cid, sizeof(cid));
}


static xqc_connection_t *
xqc_test_find_packet_conn(xqc_engine_t *engine, const unsigned char *packet,
    size_t packet_size)
{
    xqc_cid_t dcid, scid;

    xqc_cid_init_zero(&dcid);
    xqc_cid_init_zero(&scid);
    if (xqc_packet_parse_cid(&scid, &dcid, engine->config->cid_len,
                             packet, packet_size) != XQC_OK)
    {
        return NULL;
    }

    return xqc_engine_conns_hash_find(engine, &scid, 's');
}


/*
 * test_create_engine_server() (in xqc_common_test.c) loads server.key /
 * server.crt from disk and is unusable in environments without those
 * fixtures. The pre-connection drop gate under test only depends on
 * engine->eng_type and packet parsing, not on a real TLS handshake, so we
 * intentionally reuse the certificate-free client engine helper and
 * override eng_type to XQC_ENGINE_SERVER to exercise the server code path.
 */
static xqc_engine_t *
xqc_test_create_server_role_engine()
{
    xqc_engine_t *engine = test_create_engine();

    if (engine != NULL) {
        engine->eng_type = XQC_ENGINE_SERVER;
    }

    return engine;
}


static void
xqc_test_engine_small_new_conn_packet(unsigned char first_byte)
{
    unsigned char packet[XQC_PACKET_INITIAL_MIN_LENGTH];
    struct sockaddr local_addr = {0};
    struct sockaddr peer_addr = {0};
    xqc_engine_t *engine = xqc_test_create_server_role_engine();

    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
    xqc_test_build_long_header(packet, sizeof(packet), first_byte);

    xqc_int_t ret = xqc_engine_packet_process(engine, packet,
        XQC_PACKET_INITIAL_MIN_LENGTH - 1,
        &local_addr, sizeof(local_addr), &peer_addr, sizeof(peer_addr),
        xqc_monotonic_timestamp(), NULL);

    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT_PTR_NULL(xqc_test_find_packet_conn(engine, packet,
                                                 sizeof(packet) - 1));
    xqc_engine_destroy(engine);
}


void
xqc_test_engine_drop_small_initial()
{
    xqc_test_engine_small_new_conn_packet(XQC_TEST_INITIAL_FIRST_BYTE);
}


void
xqc_test_engine_drop_small_unknown_0rtt()
{
    xqc_test_engine_small_new_conn_packet(XQC_TEST_0RTT_FIRST_BYTE);
}


void
xqc_test_engine_min_initial_not_pre_dropped()
{
    unsigned char packet[XQC_PACKET_INITIAL_MIN_LENGTH];
    struct sockaddr local_addr = {0};
    struct sockaddr peer_addr = {0};
    xqc_engine_t *engine = xqc_test_create_server_role_engine();

    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
    xqc_test_build_long_header(packet, sizeof(packet), XQC_TEST_INITIAL_FIRST_BYTE);

    xqc_engine_packet_process(engine, packet, sizeof(packet),
        &local_addr, sizeof(local_addr), &peer_addr, sizeof(peer_addr),
        xqc_monotonic_timestamp(), NULL);

    CU_ASSERT_PTR_NOT_NULL(xqc_test_find_packet_conn(engine, packet,
                                                     sizeof(packet)));
    xqc_engine_destroy(engine);
}


void
xqc_test_engine_min_unknown_0rtt_not_pre_dropped()
{
    unsigned char packet[XQC_PACKET_INITIAL_MIN_LENGTH];
    struct sockaddr local_addr = {0};
    struct sockaddr peer_addr = {0};
    xqc_engine_t *engine = xqc_test_create_server_role_engine();

    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
    xqc_test_build_long_header(packet, sizeof(packet), XQC_TEST_0RTT_FIRST_BYTE);

    xqc_engine_packet_process(engine, packet, sizeof(packet),
        &local_addr, sizeof(local_addr), &peer_addr, sizeof(peer_addr),
        xqc_monotonic_timestamp(), NULL);

    CU_ASSERT_PTR_NOT_NULL(xqc_test_find_packet_conn(engine, packet,
                                                     sizeof(packet)));
    xqc_engine_destroy(engine);
}


/*
 * draft-ietf-quic-load-balancers-13: the example of Section 4.3.2 and the
 * encrypted CIDs of Appendix B.2. Server IDs and nonces of 7, 15 and 18
 * octets take the four-pass cipher, 16 octets a single pass.
 */
void
xqc_test_engine_lb_cid_vectors()
{
    static const uint8_t key_example[XQC_LB_CID_KEY_LEN] = {
        0xfd, 0xf7, 0x26, 0xa9, 0x89, 0x3e, 0xc0, 0x5c,
        0x06, 0x32, 0xd3, 0x95, 0x66, 0x80, 0xba, 0xf0,
    };
    static const uint8_t key_appendix[XQC_LB_CID_KEY_LEN] = {
        0x8f, 0x95, 0xf0, 0x92, 0x45, 0x76, 0x5f, 0x80,
        0x25, 0x69, 0x34, 0xe5, 0x0c, 0x66, 0x20, 0x7f,
    };
    static const struct {
        const uint8_t  *key;
        size_t          len;    /* server ID and nonce octets */
        uint8_t         plain[XQC_MAX_CID_LEN];  /* first octet, ID, nonce */
        uint8_t         cid[XQC_MAX_CID_LEN];
    } vectors[] = {
        {key_example, 7, {
            0x07, 0x31, 0x44, 0x1a, 0x9c, 0x69, 0xc2, 0x75,
        }, {
            0x07, 0xe2, 0x3c, 0xb4, 0x2b, 0xba, 0x1e, 0xe0,
        }},
        {key_appendix, 7, {
            0x07, 0xed, 0x79, 0x3a, 0xee, 0x08, 0x0d, 0xbf,
        }, {
            0x07, 0xfb, 0xfe, 0x05, 0xf7, 0x31, 0xb4, 0x25,
        }},
        {key_appendix, 15, {
            0x4f, 0xed, 0x79, 0x3a, 0x51, 0xd4, 0x9b, 0x8f,
            0x5f, 0xab, 0x65, 0xee, 0x08, 0x0d, 0xbf, 0x48,
        }, {
            0x4f, 0x01, 0x09, 0x56, 0xfb, 0x5c, 0x1d, 0x4d,
            0x86, 0xe0, 0x10, 0x18, 0x3e, 0x0b, 0x7d, 0x1e,
        }},
        {key_appendix, 16, {
            0x90, 0xed, 0x79, 0x3a, 0x51, 0xd4, 0x9b, 0x8f,
            0x5f, 0xee, 0x08, 0x0d, 0xbf, 0x48, 0xc0, 0xd1,
            0xe5,
        }, {
            0x90, 0x4d, 0xd2, 0xd0, 0x5a, 0x7b, 0x0d, 0xe9,
            0xb2, 0xb9, 0x90, 0x7a, 0xfb, 0x5e, 0xcf, 0x8c,
            0xc3,
        }},
        {key_appendix, 18, {
            0x12, 0xed, 0x79, 0x3a, 0x51, 0xd4, 0x9b, 0x8f,
            0x5f, 0xab, 0xee, 0x08, 0x0d, 0xbf, 0x48, 0xc0,
            0xd1, 0xe5, 0x5d,
        }, {
            0x12, 0x7a, 0x28, 0x5a, 0x09, 0xf8, 0x52, 0x80,
            0xf4, 0xfd, 0x6a, 0xbb, 0x43, 0x4a, 0x71, 0x59,
            0xe4, 0xd3, 0xeb,
        }},
    };
    uint8_t         key[XQC_LB_CID_KEY_LEN];
    uint8_t         plain[XQC_MAX_CID_LEN];
    uint8_t         cid[XQC_MAX_CID_LEN];
    xqc_engine_t   *engine = test_create_engine();

    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
    for (size_t v = 0; v < sizeof(vectors) / sizeof(vectors[0]); v++) {
        size_t len = vectors[v].len;

        memcpy(key, vectors[v].key, sizeof(key));
        memcpy(plain, vectors[v].plain, len + 1);
        memcpy(cid, plain, len + 1);
        CU_ASSERT(xqc_lb_cid_encryption(plain, len, cid, len + 1, key,
                                        sizeof(key), engine) == XQC_OK);
        CU_ASSERT(memcmp(cid, vectors[v].cid, len + 1) == 0);
    }

    xqc_engine_destroy(engine);
}


/* bit i of buf, counted from the most significant bit of buf[0] */
static uint8_t
xqc_test_lb_bit(const uint8_t *buf, size_t i)
{
    return (buf[i / 8] >> (7 - i % 8)) & 1;
}

/* copy bits [from, from + n) of src to bits [to, to + n) of dst */
static void
xqc_test_lb_copy_bits(uint8_t *dst, size_t to, const uint8_t *src,
    size_t from, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        uint8_t mask = 0x80 >> ((to + i) % 8);

        if (xqc_test_lb_bit(src, from + i)) {
            dst[(to + i) / 8] |= mask;

        } else {
            dst[(to + i) / 8] &= (uint8_t) ~mask;
        }
    }
}

/*
 * One step of the load balancer's decryption, draft-ietf-quic-load-balancers-13
 * Section 4.4.2, bit by bit on halves of bits bits stored from the most
 * significant bit: dst ^= truncate(AES_ECB(key, expand(src, pass))). Odd
 * passes use expand_left() and truncate_right(), even ones expand_right()
 * and truncate_left().
 */
static void
xqc_test_lb_decrypt_pass(uint8_t *dst, const uint8_t *src, size_t bits,
    uint8_t pass, uint8_t *key, xqc_engine_t *engine)
{
    uint8_t block[16] = {0}, cipher[16], pad[XQC_MAX_CID_LEN] = {0};
    size_t  block_bits = sizeof(block) * 8;

    if (pass % 2 == 1) {
        xqc_test_lb_copy_bits(block, 0, src, 0, bits);
        block[sizeof(block) - 1] = pass;

    } else {
        block[0] = pass;
        xqc_test_lb_copy_bits(block, block_bits - bits, src, 0, bits);
    }

    CU_ASSERT(xqc_cid_encryption_aes_128_ecb(block, sizeof(block), cipher,
                                             sizeof(cipher), key,
                                             XQC_LB_CID_KEY_LEN, engine)
              == XQC_OK);
    xqc_test_lb_copy_bits(pad, 0, cipher,
                          pass % 2 == 1 ? block_bits - bits : 0, bits);
    for (size_t i = 0; i < (bits + 7) / 8; i++) {
        dst[i] ^= pad[i];
    }
}

/*
 * A load balancer following draft-ietf-quic-load-balancers-13 Section 4.4.2
 * recovers the server ID and nonce from the CID of every four-pass length,
 * from 1 to 19 octets: odd lengths split their middle octet between the
 * halves.
 */
void
xqc_test_engine_lb_cid_decryption()
{
    uint8_t         key[XQC_LB_CID_KEY_LEN];
    uint8_t         plain[XQC_MAX_CID_LEN], cid[XQC_MAX_CID_LEN];
    uint8_t         left[XQC_MAX_CID_LEN], right[XQC_MAX_CID_LEN];
    uint8_t         decrypted[XQC_MAX_CID_LEN];
    xqc_engine_t   *engine = test_create_engine();

    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
    for (size_t i = 0; i < sizeof(key); i++) {
        key[i] = (uint8_t) (0x5a ^ (0x13 * i));
    }

    for (size_t len = 1; len < XQC_MAX_CID_LEN; len++) {
        size_t bits = len * 4;

        if (len == XQC_LB_CID_KEY_LEN) {
            continue;   /* a single AES pass */
        }

        for (size_t i = 0; i <= len; i++) {
            plain[i] = (uint8_t) (0x3d * (i + len) + 0x21);
        }
        memcpy(cid, plain, len + 1);
        CU_ASSERT(xqc_lb_cid_encryption(plain, len, cid, len + 1, key,
                                        sizeof(key), engine) == XQC_OK);

        xqc_memzero(left, sizeof(left));
        xqc_memzero(right, sizeof(right));
        xqc_test_lb_copy_bits(left, 0, cid + 1, 0, bits);
        xqc_test_lb_copy_bits(right, 0, cid + 1, bits, bits);
        xqc_test_lb_decrypt_pass(left, right, bits, 4, key, engine);
        xqc_test_lb_decrypt_pass(right, left, bits, 3, key, engine);
        xqc_test_lb_decrypt_pass(left, right, bits, 2, key, engine);
        xqc_test_lb_decrypt_pass(right, left, bits, 1, key, engine);

        xqc_memzero(decrypted, sizeof(decrypted));
        xqc_test_lb_copy_bits(decrypted, 0, left, 0, bits);
        xqc_test_lb_copy_bits(decrypted, bits, right, 0, bits);
        CU_ASSERT(memcmp(decrypted, plain + 1, len) == 0);
        CU_ASSERT(cid[0] == plain[0]);
    }

    xqc_engine_destroy(engine);
}


/*
 * Every encrypted length of a load balancer CID: 16 bytes take one AES
 * pass, the others the four-pass cipher, whose truncations shift by more
 * than a byte for the long lengths. Each CID is encrypted into a buffer of
 * exactly its length, followed by a guard byte that must stay intact.
 * Encryption is deterministic and keeps the first octet; lengths and keys
 * out of range are refused.
 */
void
xqc_test_engine_lb_cid_encryption()
{
    uint8_t key[XQC_LB_CID_KEY_LEN];
    uint8_t in[XQC_MAX_CID_LEN];
    uint8_t out1[XQC_MAX_CID_LEN + 1], out2[XQC_MAX_CID_LEN + 1];
    xqc_engine_t *engine = test_create_engine();

    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
    for (size_t i = 0; i < sizeof(key); i++) {
        key[i] = (uint8_t) (0x30 + i);
    }
    for (size_t i = 0; i < sizeof(in); i++) {
        in[i] = (uint8_t) (0x11 * i + 7);
    }

    for (size_t len = 1; len < XQC_MAX_CID_LEN; len++) {
        memcpy(out1, in, len + 1);
        memcpy(out2, in, len + 1);
        out1[len + 1] = 0xa5;
        out2[len + 1] = 0xa5;
        CU_ASSERT(xqc_lb_cid_encryption(in, len, out1, len + 1,
                                        key, sizeof(key), engine) == XQC_OK);
        CU_ASSERT(xqc_lb_cid_encryption(in, len, out2, len + 1,
                                        key, sizeof(key), engine) == XQC_OK);
        CU_ASSERT(memcmp(out1, out2, len + 1) == 0);
        CU_ASSERT(out1[0] == in[0]);
        CU_ASSERT(out1[len + 1] == 0xa5);
    }

    /* abnormal: too long, a short output buffer, a wrong key length */
    CU_ASSERT(xqc_lb_cid_encryption(in, XQC_MAX_CID_LEN, out1, sizeof(out1),
                                    key, sizeof(key), engine) == -XQC_EPARAM);
    CU_ASSERT(xqc_lb_cid_encryption(in, 8, out1, 8, key, sizeof(key),
                                    engine) == -XQC_EPARAM);
    CU_ASSERT(xqc_lb_cid_encryption(in, 8, out1, sizeof(out1), key,
                                    sizeof(key) - 1, engine) == -XQC_EPARAM);

    xqc_engine_destroy(engine);
}


void
xqc_test_rebinding_candidate_budget_limit()
{
    xqc_connection_t *conn = test_engine_connect();
    xqc_path_ctx_t *path;
    struct sockaddr_in addr;
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    path = conn->conn_initial_path;
    CU_ASSERT_PTR_NOT_NULL_FATAL(path);
    conn->conn_type = XQC_CONN_TYPE_SERVER;
    conn->conn_flag &= ~XQC_CONN_FLAG_HANDSHAKE_CONFIRMED;
    xqc_memzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;

    ret = xqc_path_rebinding_on_authenticated_datagram(conn, path,
        (struct sockaddr *)&addr, sizeof(addr), 399, xqc_monotonic_timestamp());
    CU_ASSERT_EQUAL(ret, -XQC_EAGAIN);
    CU_ASSERT_EQUAL(path->rebinding.state, XQC_REBINDING_ADDRESS_VALIDATING);
    CU_ASSERT_EQUAL(path->rebinding.recv_bytes, 399);
    CU_ASSERT_EQUAL(path->rebinding.sent_bytes, 0);

    ret = xqc_path_rebinding_on_authenticated_datagram(conn, path,
        (struct sockaddr *)&addr, sizeof(addr), 1, xqc_monotonic_timestamp());
    CU_ASSERT_EQUAL(ret, -XQC_EAGAIN);
    CU_ASSERT_EQUAL(path->rebinding.recv_bytes, 400);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_rebinding_no_padding_flag()
{
    xqc_connection_t conn;
    xqc_engine_t engine;
    xqc_packet_out_t packet_out;

    xqc_memzero(&conn, sizeof(conn));
    xqc_memzero(&engine, sizeof(engine));
    xqc_memzero(&packet_out, sizeof(packet_out));

    conn.engine = &engine;
    engine.eng_type = XQC_ENGINE_SERVER;
    packet_out.po_pkt.pkt_pns = XQC_PNS_APP_DATA;
    packet_out.po_frame_types = XQC_FRAME_BIT_PATH_CHALLENGE;

    CU_ASSERT_TRUE(xqc_need_padding(&conn, &packet_out));

    packet_out.po_flag |= XQC_POF_NO_PATH_PADDING;
    CU_ASSERT_FALSE(xqc_need_padding(&conn, &packet_out));

    packet_out.po_flag &= ~XQC_POF_NO_PATH_PADDING;
    packet_out.po_flag |= XQC_POF_PATH_MIN_PADDING;
    CU_ASSERT_TRUE(xqc_need_padding(&conn, &packet_out));
}


void
xqc_test_rebinding_min_padding_flag()
{
    xqc_connection_t conn;
    xqc_packet_out_t packet_out;
    unsigned char buf[1500];

    xqc_memzero(&conn, sizeof(conn));
    xqc_memzero(&packet_out, sizeof(packet_out));
    xqc_memzero(buf, sizeof(buf));

    conn.enable_pmtud = 1;
    packet_out.po_buf = buf;
    packet_out.po_buf_size = 1300;
    packet_out.po_used_size = 20;
    packet_out.po_frame_types = XQC_FRAME_BIT_PATH_CHALLENGE;
    packet_out.po_flag = XQC_POF_PATH_MIN_PADDING;

    xqc_gen_padding_frame(&conn, &packet_out);
    CU_ASSERT_EQUAL(packet_out.po_used_size,
                    XQC_PACKET_INITIAL_MIN_LENGTH - XQC_TLS_AEAD_OVERHEAD_MAX_LEN);
}


void
xqc_test_rebinding_response_state_transition()
{
    xqc_connection_t *conn = test_engine_connect();
    xqc_path_ctx_t *path;
    struct sockaddr_in addr;
    unsigned char response_data[XQC_PATH_CHALLENGE_DATA_LEN];
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    path = conn->conn_initial_path;
    CU_ASSERT_PTR_NOT_NULL_FATAL(path);
    conn->conn_type = XQC_CONN_TYPE_SERVER;
    conn->conn_flag &= ~XQC_CONN_FLAG_HANDSHAKE_CONFIRMED;
    xqc_memzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4433);
    CU_ASSERT_EQUAL(xqc_memcpy_with_cap(path->rebinding.addr,
                                        sizeof(path->rebinding.addr), &addr,
                                        sizeof(addr)), XQC_OK);
    path->rebinding.addrlen = sizeof(addr);
    path->rebinding.state = XQC_REBINDING_ADDRESS_VALIDATING;
    path->rebinding.initial_challenge_padded = XQC_FALSE;
    memset(path->rebinding.challenge_data, 0x5a,
           sizeof(path->rebinding.challenge_data));

    ret = xqc_path_rebinding_on_response(conn, path,
                                         path->rebinding.challenge_data,
                                         xqc_monotonic_timestamp());
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(path->rebinding.state, XQC_REBINDING_MTU_VALIDATING);
    CU_ASSERT_EQUAL(path->rebinding.valid, 1);
    CU_ASSERT_TRUE(xqc_is_same_addr((struct sockaddr *)&addr,
                                    (struct sockaddr *)path->peer_addr));

    xqc_memcpy(response_data, path->rebinding.challenge_data, sizeof(response_data));
    ret = xqc_path_rebinding_on_response(conn, path, response_data,
                                         xqc_monotonic_timestamp());
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(path->rebinding.state, XQC_REBINDING_IDLE);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_rebinding_clear()
{
    xqc_path_ctx_t path;

    xqc_memzero(&path, sizeof(path));
    path.rebinding.addrlen = sizeof(struct sockaddr_in);
    path.rebinding.recv_bytes = 1200;
    path.rebinding.sent_bytes = 1200;
    path.rebinding.state = XQC_REBINDING_MTU_VALIDATING;
    path.rebinding.initial_challenge_padded = XQC_TRUE;
    path.rebinding.mtu_probe_retries = 2;
    path.rebinding.count = 3;
    path.rebinding.valid = 2;

    xqc_path_rebinding_clear(&path);
    CU_ASSERT_EQUAL(path.rebinding.addrlen, 0);
    CU_ASSERT_EQUAL(path.rebinding.recv_bytes, 0);
    CU_ASSERT_EQUAL(path.rebinding.sent_bytes, 0);
    CU_ASSERT_EQUAL(path.rebinding.state, XQC_REBINDING_IDLE);
    CU_ASSERT_FALSE(path.rebinding.initial_challenge_padded);
    CU_ASSERT_EQUAL(path.rebinding.mtu_probe_retries, 0);
    CU_ASSERT_EQUAL(path.rebinding.count, 3);
    CU_ASSERT_EQUAL(path.rebinding.valid, 2);
}


void
xqc_test_rebinding_ignores_unauthenticated_packet()
{
    xqc_connection_t *conn = test_engine_connect();
    unsigned char packet[] = {0};
    uint32_t authenticated_before;
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    authenticated_before = conn->rcv_pkt_stats.conn_authenticated_pkts;
    ret = xqc_conn_process_packet(conn, packet, sizeof(packet),
                                  xqc_monotonic_timestamp());
    CU_ASSERT_EQUAL(ret, XQC_OK);
    CU_ASSERT_EQUAL(conn->rcv_pkt_stats.conn_authenticated_pkts,
                    authenticated_before);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_rebinding_path_challenge_requires_confirmed()
{
    xqc_connection_t *conn = test_engine_connect();
    struct sockaddr_in addr;
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn->conn_initial_path);

    conn->conn_type = XQC_CONN_TYPE_SERVER;
    conn->conn_flag &= ~XQC_CONN_FLAG_HANDSHAKE_CONFIRMED;
    xqc_memzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;

    ret = xqc_path_rebinding_on_authenticated_datagram(conn, conn->conn_initial_path,
        (struct sockaddr *)&addr, sizeof(addr), 1200, xqc_monotonic_timestamp());
    CU_ASSERT_EQUAL(ret, -XQC_EAGAIN);
    CU_ASSERT_EQUAL(conn->conn_initial_path->rebinding.state,
                    XQC_REBINDING_ADDRESS_VALIDATING);
    CU_ASSERT_EQUAL(conn->conn_initial_path->rebinding.sent_bytes, 0);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_rebinding_timeout_retry_limit()
{
    xqc_connection_t *conn = test_engine_connect();
    xqc_path_ctx_t *path;
    struct sockaddr_in addr;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    path = conn->conn_initial_path;
    CU_ASSERT_PTR_NOT_NULL_FATAL(path);

    conn->conn_type = XQC_CONN_TYPE_SERVER;
    conn->conn_flag &= ~XQC_CONN_FLAG_HANDSHAKE_CONFIRMED;
    xqc_memzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    CU_ASSERT_EQUAL(xqc_memcpy_with_cap(path->rebinding.addr,
                                        sizeof(path->rebinding.addr), &addr,
                                        sizeof(addr)), XQC_OK);
    path->rebinding.addrlen = sizeof(addr);
    path->rebinding.recv_bytes = 400;
    path->rebinding.state = XQC_REBINDING_MTU_VALIDATING;
    path->rebinding.mtu_probe_retries = XQC_REBINDING_MAX_MTU_PROBE_RETRIES - 1;

    xqc_path_rebinding_on_timeout(conn, path, xqc_monotonic_timestamp());
    CU_ASSERT_EQUAL(path->rebinding.state, XQC_REBINDING_MTU_VALIDATING);
    CU_ASSERT_EQUAL(path->rebinding.mtu_probe_retries,
                    XQC_REBINDING_MAX_MTU_PROBE_RETRIES);
    CU_ASSERT_TRUE(xqc_timer_is_set(&path->path_send_ctl->path_timer_manager,
                                    XQC_TIMER_NAT_REBINDING));

    xqc_path_rebinding_on_timeout(conn, path, xqc_monotonic_timestamp());
    CU_ASSERT_EQUAL(path->rebinding.state, XQC_REBINDING_IDLE);
    CU_ASSERT_EQUAL(path->rebinding.addrlen, 0);
    CU_ASSERT_EQUAL(path->rebinding.mtu_probe_retries, 0);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_rebinding_response_mismatch_preserves_state()
{
    xqc_connection_t *conn = test_engine_connect();
    xqc_path_ctx_t *path;
    unsigned char mismatch_data[XQC_PATH_CHALLENGE_DATA_LEN] = {0};
    xqc_usec_t now;
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    path = conn->conn_initial_path;
    CU_ASSERT_PTR_NOT_NULL_FATAL(path);

    path->rebinding.state = XQC_REBINDING_ADDRESS_VALIDATING;
    path->rebinding.recv_bytes = 400;
    path->rebinding.sent_bytes = 100;
    path->rebinding.valid = 2;
    memset(path->rebinding.challenge_data, 0x5a,
           sizeof(path->rebinding.challenge_data));
    now = xqc_monotonic_timestamp();
    xqc_timer_set(&path->path_send_ctl->path_timer_manager, XQC_TIMER_NAT_REBINDING,
                  now, 1);

    ret = xqc_path_rebinding_on_response(conn, path, mismatch_data, now);
    CU_ASSERT_EQUAL(ret, XQC_ERROR);
    CU_ASSERT_EQUAL(path->rebinding.state, XQC_REBINDING_ADDRESS_VALIDATING);
    CU_ASSERT_EQUAL(path->rebinding.recv_bytes, 400);
    CU_ASSERT_EQUAL(path->rebinding.sent_bytes, 100);
    CU_ASSERT_EQUAL(path->rebinding.valid, 2);
    CU_ASSERT_EQUAL(memcmp(path->rebinding.challenge_data, mismatch_data,
                           sizeof(mismatch_data)) != 0, XQC_TRUE);
    CU_ASSERT_TRUE(xqc_timer_is_set(&path->path_send_ctl->path_timer_manager,
                                    XQC_TIMER_NAT_REBINDING));

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_rebinding_sender_error_clears_candidate()
{
    xqc_connection_t *conn = test_engine_connect();
    xqc_path_ctx_t *path;
    struct sockaddr_in addr;
    xqc_int_t ret;

    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    path = conn->conn_initial_path;
    CU_ASSERT_PTR_NOT_NULL_FATAL(path);

    xqc_memzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    conn->transport_cbs.write_socket_ex = NULL;
    ret = xqc_path_rebinding_on_authenticated_datagram(conn, path,
        (struct sockaddr *)&addr, sizeof(addr), 400, xqc_monotonic_timestamp());
    CU_ASSERT_EQUAL(ret, XQC_ERROR);
    CU_ASSERT_EQUAL(path->rebinding.state, XQC_REBINDING_IDLE);
    CU_ASSERT_EQUAL(path->rebinding.addrlen, 0);
    CU_ASSERT_EQUAL(path->rebinding.recv_bytes, 0);
    CU_ASSERT_EQUAL(path->rebinding.sent_bytes, 0);

    xqc_engine_destroy(conn->engine);
}


void
xqc_test_engine_packet_process()
{
    struct sockaddr local_addr;
    socklen_t local_addrlen = 0;
    struct sockaddr peer_addr;
    socklen_t peer_addrlen = 0;

    xqc_engine_t *engine = test_create_engine_server();
    CU_ASSERT(engine != NULL);
    if (engine == NULL) {
        return;
    }

    xqc_msec_t recv_time = xqc_monotonic_timestamp();

    xqc_int_t rc = xqc_engine_packet_process(engine, XQC_TEST_LONG_HEADER_PACKET_B,
                                             sizeof(XQC_TEST_LONG_HEADER_PACKET_B) - 1,
                                             (struct sockaddr *)(&local_addr), local_addrlen,
                                             (struct sockaddr *)(&peer_addr), peer_addrlen,
                                             recv_time, NULL);                                          
    //CU_ASSERT(rc == XQC_OK);

    /* get connection */
    xqc_cid_t dcid, scid;
    xqc_cid_init_zero(&dcid);
    xqc_cid_init_zero(&scid);

    rc = xqc_packet_parse_cid(&scid, &dcid, engine->config->cid_len, XQC_TEST_LONG_HEADER_PACKET_B,
                              sizeof(XQC_TEST_LONG_HEADER_PACKET_B) - 1);
    CU_ASSERT(rc == XQC_OK);

    /*
     * This packet is synthetic and does not complete a TLS handshake.  Do not
     * force 1-RTT short-header processing without installed packet keys.
     */
    xqc_engine_destroy(engine);
}
