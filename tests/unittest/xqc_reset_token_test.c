/*
 * A stateless reset token MUST be difficult to guess, and MUST NOT be
 * shared by connection IDs (RFC 9000 Section 10.3.2). When the HMAC that
 * derives it fails, as BabaSSL's can (it allocates its context), the token
 * is random. When random bytes cannot be had either, there is no token, and
 * nothing uses one: the connection ID is not issued, the server connection
 * is not created, the transport parameter is left out, and no stateless
 * reset is sent or recognised.
 *
 * On Linux, run_tests is linked with --wrap for the allocation functions
 * (xqc_alloc_wrap.h), HMAC() and RAND_bytes() (tests/CMakeLists.txt): the
 * tests make them fail.
 */

#include <CUnit/CUnit.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include "src/common/xqc_time.h"
#include "src/transport/xqc_cid.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_packet_parser.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_transport_params.h"
#include "xqc_alloc_wrap.h"
#include "xqc_common_test.h"
#include "xqc_reset_token_test.h"

#ifdef XQC_TEST_ALLOC_WRAP

/* while set, HMAC() and RAND_bytes() fail */
static int xqc_test_hmac_fail;
static int xqc_test_rand_fail;

#ifdef OPENSSL_IS_BORINGSSL
typedef size_t xqc_test_hmac_key_len_t;
typedef size_t xqc_test_rand_len_t;
#else
/* OpenSSL 1.1.1, which BabaSSL is based on */
typedef int    xqc_test_hmac_key_len_t;
typedef int    xqc_test_rand_len_t;
#endif

/* the prototypes of the library, which the definitions below must match */
__typeof__(HMAC) __real_HMAC, __wrap_HMAC;
__typeof__(RAND_bytes) __real_RAND_bytes, __wrap_RAND_bytes;

unsigned char *
__wrap_HMAC(const EVP_MD *evp_md, const void *key,
    xqc_test_hmac_key_len_t key_len, const unsigned char *data,
    size_t data_len, unsigned char *out, unsigned int *out_len)
{
    if (xqc_test_hmac_fail) {
        return NULL;
    }
    return __real_HMAC(evp_md, key, key_len, data, data_len, out, out_len);
}

int
__wrap_RAND_bytes(unsigned char *buf, xqc_test_rand_len_t len)
{
    if (xqc_test_rand_fail) {
        return 0;
    }
    return __real_RAND_bytes(buf, len);
}

static void
xqc_test_rt_fail(int hmac_fail, int rand_fail)
{
    xqc_test_hmac_fail = hmac_fail;
    xqc_test_rand_fail = rand_fail;
}

static void
xqc_test_rt_cid(xqc_cid_t *cid, size_t len, unsigned char byte)
{
    memset(cid, 0, sizeof(*cid));
    cid->cid_len = len;
    memset(cid->cid_buf, byte, len);
}

/* the token that the engine derives for cid */
static void
xqc_test_rt_derive(xqc_engine_t *engine, xqc_cid_t *cid, unsigned char *token)
{
    CU_ASSERT(xqc_gen_reset_token(cid, token, XQC_STATELESS_RESET_TOKENLEN,
                                  engine->config->reset_token_key,
                                  engine->config->reset_token_keylen)
              == XQC_OK);
}

void
xqc_test_reset_token_alloc_failure(void)
{
    static const unsigned char zero[XQC_STATELESS_RESET_TOKENLEN];
    unsigned char token[XQC_STATELESS_RESET_TOKENLEN];
    unsigned char again[XQC_STATELESS_RESET_TOKENLEN];
    char key[] = "reset token key";
    xqc_cid_t cid;
    xqc_int_t ret;

    xqc_test_rt_cid(&cid, 8, 0xab);

    /* derived from the key and the connection ID when nothing fails */
    CU_ASSERT(xqc_gen_reset_token(&cid, token, sizeof(token), key,
                                  sizeof(key) - 1) == XQC_OK);
    CU_ASSERT(xqc_gen_reset_token(&cid, again, sizeof(again), key,
                                  sizeof(key) - 1) == XQC_OK);
    CU_ASSERT(memcmp(token, again, sizeof(token)) == 0);
    CU_ASSERT(memcmp(token, zero, sizeof(token)) != 0);

    /* the first allocation of the derivation fails, if it makes one */
    xqc_test_alloc_failed = 0;
    xqc_test_alloc_fail_at = 1;
    xqc_test_alloc_count = 0;
    ret = xqc_gen_reset_token(&cid, again, sizeof(again), key, sizeof(key) - 1);
    xqc_test_alloc_count = -1;
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(memcmp(again, zero, sizeof(again)) != 0);
    if (xqc_test_alloc_failed) {
        CU_ASSERT(memcmp(again, token, sizeof(again)) != 0);

    } else {
        CU_ASSERT(memcmp(again, token, sizeof(again)) == 0);
    }
}

void
xqc_test_reset_token_crypto_failure(void)
{
    static const unsigned char zero[XQC_STATELESS_RESET_TOKENLEN];
    unsigned char derived[XQC_STATELESS_RESET_TOKENLEN];
    unsigned char token[XQC_STATELESS_RESET_TOKENLEN];
    unsigned char again[XQC_STATELESS_RESET_TOKENLEN];
    char key[] = "reset token key";
    size_t keylen = sizeof(key) - 1;
    xqc_cid_t cid;
    xqc_int_t ret1, ret2;

    xqc_test_rt_cid(&cid, 8, 0xab);
    CU_ASSERT(xqc_gen_reset_token(&cid, derived, sizeof(derived), key, keylen)
              == XQC_OK);

    /* HMAC() fails: a random token, another one each time */
    xqc_test_rt_fail(1, 0);
    ret1 = xqc_gen_reset_token(&cid, token, sizeof(token), key, keylen);
    ret2 = xqc_gen_reset_token(&cid, again, sizeof(again), key, keylen);
    xqc_test_rt_fail(0, 0);
    CU_ASSERT(ret1 == XQC_OK);
    CU_ASSERT(ret2 == XQC_OK);
    CU_ASSERT(memcmp(token, derived, sizeof(token)) != 0);
    CU_ASSERT(memcmp(token, zero, sizeof(token)) != 0);
    CU_ASSERT(memcmp(token, again, sizeof(token)) != 0);

    /* RAND_bytes() fails as well: no token, and nothing written */
    memset(token, 0xee, sizeof(token));
    memset(again, 0xee, sizeof(again));
    xqc_test_rt_fail(1, 1);
    ret1 = xqc_gen_reset_token(&cid, token, sizeof(token), key, keylen);
    xqc_test_rt_fail(0, 0);
    CU_ASSERT(ret1 == -XQC_ESYS);
    CU_ASSERT(memcmp(token, again, sizeof(token)) == 0);

    /* RAND_bytes() is not needed when HMAC() succeeds */
    xqc_test_rt_fail(0, 1);
    ret1 = xqc_gen_reset_token(&cid, token, sizeof(token), key, keylen);
    xqc_test_rt_fail(0, 0);
    CU_ASSERT(ret1 == XQC_OK);
    CU_ASSERT(memcmp(token, derived, sizeof(token)) == 0);
}

static unsigned char xqc_test_rt_cid_byte;

/* connection IDs made of xqc_test_rt_cid_byte, to know them in advance */
static ssize_t
xqc_test_rt_cid_generate(const xqc_cid_t *ori_cid, uint8_t *cid_buf,
    size_t cid_buflen, void *engine_user_data)
{
    memset(cid_buf, xqc_test_rt_cid_byte, cid_buflen);
    return cid_buflen;
}

/*
 * Issue a connection ID made of byte on path_id, through the multipath
 * frame when mp is set. With both HMAC() and RAND_bytes() failing, check
 * that nothing changed: the sequence number is still free, and the
 * connection ID is neither stored nor routed nor sent. Otherwise, check
 * that it was issued with seq_num, and with the derived token, or with a
 * random one when HMAC() fails.
 */
static void
xqc_test_rt_issue_cid(xqc_connection_t *conn, uint64_t path_id, int mp,
    unsigned char byte, int hmac_fail, int rand_fail, uint64_t seq_num)
{
    static const unsigned char zero[XQC_STATELESS_RESET_TOKENLEN];
    unsigned char           derived[XQC_STATELESS_RESET_TOKENLEN];
    const unsigned char    *sent;
    xqc_cid_set_inner_t    *inner_set;
    xqc_cid_inner_t        *inner_cid;
    xqc_packet_out_t       *packet_out;
    xqc_send_queue_t       *sndq = conn->conn_send_queue;
    uint64_t                largest, unused, used_pkts;
    xqc_cid_t               cid;
    xqc_int_t               ret;

    inner_set = xqc_get_path_cid_set(&conn->scid_set, path_id);
    CU_ASSERT_PTR_NOT_NULL_FATAL(inner_set);
    largest = inner_set->largest_scid_seq_num;
    unused = inner_set->unused_cnt;
    used_pkts = sndq->sndq_packets_used;

    xqc_test_rt_cid(&cid, conn->engine->config->cid_len, byte);
    xqc_test_rt_derive(conn->engine, &cid, derived);
    xqc_test_rt_cid_byte = byte;

    xqc_test_rt_fail(hmac_fail, rand_fail);
    if (mp) {
        ret = xqc_write_mp_new_conn_id_frame_to_packet(conn, 0, path_id);

    } else {
        ret = xqc_write_new_conn_id_frame_to_packet(conn, 0);
    }
    xqc_test_rt_fail(0, 0);

    if (hmac_fail && rand_fail) {
        CU_ASSERT(ret == -XQC_ESYS);
        CU_ASSERT(inner_set->largest_scid_seq_num == largest);
        CU_ASSERT(inner_set->unused_cnt == unused);
        CU_ASSERT(xqc_cid_in_cid_set(&conn->scid_set, &cid, path_id) == NULL);
        CU_ASSERT(xqc_engine_conns_hash_find(conn->engine, &cid, 's') == NULL);
        CU_ASSERT(sndq->sndq_packets_used == used_pkts);
        return;
    }

    CU_ASSERT_FATAL(ret == XQC_OK);
    CU_ASSERT(inner_set->largest_scid_seq_num == seq_num);
    CU_ASSERT(inner_set->unused_cnt == unused + 1);
    inner_cid = xqc_cid_in_cid_set(&conn->scid_set, &cid, path_id);
    CU_ASSERT_PTR_NOT_NULL_FATAL(inner_cid);
    CU_ASSERT(inner_cid->cid.cid_seq_num == seq_num);
    CU_ASSERT(xqc_engine_conns_hash_find(conn->engine, &cid, 's') == conn);
    CU_ASSERT_FATAL(sndq->sndq_packets_used == used_pkts + 1);

    /* the frame, the last one queued, ends with the token */
    packet_out = xqc_list_entry(sndq->sndq_send_packets_high_pri.prev,
                                xqc_packet_out_t, po_list);
    CU_ASSERT(packet_out->po_new_cid_seq == seq_num);
    CU_ASSERT(packet_out->po_new_cid_path == path_id);
    sent = packet_out->po_buf + packet_out->po_used_size
           - XQC_STATELESS_RESET_TOKENLEN;
    if (!hmac_fail) {
        CU_ASSERT(memcmp(sent, derived, XQC_STATELESS_RESET_TOKENLEN) == 0);

    } else {
        CU_ASSERT(memcmp(sent, derived, XQC_STATELESS_RESET_TOKENLEN) != 0);
        CU_ASSERT(memcmp(sent, zero, XQC_STATELESS_RESET_TOKENLEN) != 0);
    }
}

static xqc_connection_t *
xqc_test_rt_cid_conn(void)
{
    xqc_connection_t *conn;

    conn = test_engine_connect();
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    conn->engine->eng_callback.cid_generate_cb = xqc_test_rt_cid_generate;
    conn->remote_settings.active_connection_id_limit =
        XQC_CONN_ACTIVE_CID_LIMIT;
    return conn;
}

void
xqc_test_reset_token_new_cid_failure(void)
{
    xqc_connection_t       *conn;
    xqc_cid_set_inner_t    *inner_set;
    uint64_t                seq;

    /* NEW_CONNECTION_ID */
    conn = xqc_test_rt_cid_conn();
    inner_set = xqc_get_path_cid_set(&conn->scid_set, XQC_INITIAL_PATH_ID);
    CU_ASSERT_PTR_NOT_NULL_FATAL(inner_set);
    seq = inner_set->largest_scid_seq_num;

    xqc_test_rt_issue_cid(conn, XQC_INITIAL_PATH_ID, 0, 0x51, 1, 1, 0);
    /* the next connection ID takes the sequence number that was not used */
    xqc_test_rt_issue_cid(conn, XQC_INITIAL_PATH_ID, 0, 0x52, 0, 0, seq + 1);
    /* HMAC() failing alone gives a random token */
    xqc_test_rt_issue_cid(conn, XQC_INITIAL_PATH_ID, 0, 0x53, 1, 0, seq + 2);
    xqc_engine_destroy(conn->engine);

    /*
     * MP_NEW_CONNECTION_ID: path ID 1 has no connection ID yet, so its
     * first one gets sequence number 0, and path ID 0's next one the
     * number after that of its first
     */
    conn = xqc_test_rt_cid_conn();
    conn->enable_multipath = XQC_CONN_MP_ENABLED;
    conn->conn_settings.multipath_version = XQC_MULTIPATH_10;
    conn->local_max_path_id = 1;
    conn->remote_max_path_id = 1;
    conn->curr_max_path_id = 1;
    CU_ASSERT_FATAL(xqc_conn_add_path_cid_sets(conn, 1, 1) == XQC_OK);
    inner_set = xqc_get_path_cid_set(&conn->scid_set, XQC_INITIAL_PATH_ID);
    CU_ASSERT_PTR_NOT_NULL_FATAL(inner_set);
    seq = inner_set->largest_scid_seq_num;

    xqc_test_rt_issue_cid(conn, 1, 1, 0x61, 1, 1, 0);
    xqc_test_rt_issue_cid(conn, 1, 1, 0x62, 0, 0, 0);
    xqc_test_rt_issue_cid(conn, XQC_INITIAL_PATH_ID, 1, 0x63, 1, 1, 0);
    xqc_test_rt_issue_cid(conn, XQC_INITIAL_PATH_ID, 1, 0x64, 0, 0, seq + 1);
    xqc_engine_destroy(conn->engine);
}

static void
xqc_test_rt_addrs(struct sockaddr_in *local, struct sockaddr_in *peer)
{
    memset(local, 0, sizeof(*local));
    local->sin_family = AF_INET;
    local->sin_port = htons(4433);
    local->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    *peer = *local;
    peer->sin_port = htons(5555);
}

/* the server's connection for a client's first packet sent to scid */
static xqc_connection_t *
xqc_test_rt_server_create(xqc_engine_t *engine, xqc_cid_t *dcid,
    xqc_cid_t *scid, int hmac_fail, int rand_fail)
{
    struct sockaddr_in  local, peer;
    xqc_connection_t   *conn;

    xqc_test_rt_addrs(&local, &peer);
    xqc_test_rt_fail(hmac_fail, rand_fail);
    conn = xqc_conn_server_create(engine, (struct sockaddr *)&local,
                                  sizeof(local), (struct sockaddr *)&peer,
                                  sizeof(peer), dcid, scid,
                                  &engine->default_conn_settings, NULL);
    xqc_test_rt_fail(0, 0);
    return conn;
}

void
xqc_test_reset_token_server_failure(void)
{
    static const unsigned char zero[XQC_STATELESS_RESET_TOKENLEN];
    unsigned char           derived[XQC_STATELESS_RESET_TOKENLEN];
    unsigned char           tp_buf[XQC_MAX_TRANSPORT_PARAM_BUF_LEN];
    size_t                  tp_len = 0;
    xqc_transport_params_t  params, decoded;
    xqc_connection_t       *conn;
    xqc_engine_t           *engine;
    xqc_cid_t               dcid, scid;
    xqc_int_t               ret;

    engine = test_create_engine_server();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);

    /*
     * The client's connection ID, and the one it chose for the server, of
     * the server's length: the server keeps it, and its first connection
     * ID is also the original destination connection ID.
     */
    xqc_test_rt_cid(&dcid, engine->config->cid_len, 0x71);
    xqc_test_rt_cid(&scid, engine->config->cid_len, 0x72);
    xqc_test_rt_derive(engine, &scid, derived);

    /* no token: no connection */
    conn = xqc_test_rt_server_create(engine, &dcid, &scid, 1, 1);
    CU_ASSERT(conn == NULL);
    CU_ASSERT(xqc_engine_conns_hash_find(engine, &scid, 's') == NULL);

    /* created once a token can be made */
    conn = xqc_test_rt_server_create(engine, &dcid, &scid, 0, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    CU_ASSERT(xqc_engine_conns_hash_find(engine, &scid, 's') == conn);
    CU_ASSERT(memcmp(conn->scid_set.user_scid.sr_token, derived,
                     XQC_STATELESS_RESET_TOKENLEN) == 0);

    /* the transport parameter carries the same token */
    memset(&params, 0, sizeof(params));
    CU_ASSERT(xqc_conn_get_local_transport_params(conn, &params) == XQC_OK);
    CU_ASSERT(params.original_dest_connection_id_present == 1);
    CU_ASSERT(params.stateless_reset_token_present == 1);
    CU_ASSERT(memcmp(params.stateless_reset_token, derived,
                     XQC_STATELESS_RESET_TOKENLEN) == 0);

    /* and is left out, as it is optional, when no token can be made */
    memset(&params, 0, sizeof(params));
    xqc_test_rt_fail(1, 1);
    ret = xqc_conn_get_local_transport_params(conn, &params);
    xqc_test_rt_fail(0, 0);
    CU_ASSERT(ret == XQC_OK);
    CU_ASSERT(params.original_dest_connection_id_present == 1);
    CU_ASSERT(params.stateless_reset_token_present == 0);
    CU_ASSERT(xqc_encode_transport_params(&params,
                                          XQC_TP_TYPE_ENCRYPTED_EXTENSIONS,
                                          tp_buf, sizeof(tp_buf), &tp_len)
              == XQC_OK);
    memset(&decoded, 0, sizeof(decoded));
    CU_ASSERT(xqc_decode_transport_params(&decoded,
                                          XQC_TP_TYPE_ENCRYPTED_EXTENSIONS,
                                          tp_buf, tp_len) == XQC_OK);
    CU_ASSERT(decoded.original_dest_connection_id_present == 1);
    CU_ASSERT(decoded.stateless_reset_token_present == 0);
    xqc_conn_destroy(conn);

    /* HMAC() failing alone gives a random token */
    xqc_test_rt_cid(&scid, engine->config->cid_len, 0x73);
    xqc_test_rt_derive(engine, &scid, derived);
    conn = xqc_test_rt_server_create(engine, &dcid, &scid, 1, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    CU_ASSERT(memcmp(conn->scid_set.user_scid.sr_token, derived,
                     XQC_STATELESS_RESET_TOKENLEN) != 0);
    CU_ASSERT(memcmp(conn->scid_set.user_scid.sr_token, zero,
                     XQC_STATELESS_RESET_TOKENLEN) != 0);
    xqc_conn_destroy(conn);

    xqc_engine_destroy(engine);
}

static int              xqc_test_rt_sr_count;
static unsigned char    xqc_test_rt_sr_pkt[XQC_PACKET_OUT_BUF_CAP];
static size_t           xqc_test_rt_sr_len;

static ssize_t
xqc_test_rt_stateless_reset(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    const struct sockaddr *local_addr, socklen_t local_addrlen,
    void *user_data)
{
    xqc_test_rt_sr_count++;
    if (size <= sizeof(xqc_test_rt_sr_pkt)) {
        memcpy(xqc_test_rt_sr_pkt, buf, size);
        xqc_test_rt_sr_len = size;
    }
    return size;
}

/* a packet of a connection that the server does not know */
static xqc_int_t
xqc_test_rt_unknown_packet(xqc_engine_t *engine, unsigned char *pkt,
    size_t len, int fail)
{
    struct sockaddr_in  local, peer;
    xqc_int_t           ret;

    xqc_test_rt_addrs(&local, &peer);
    xqc_test_rt_fail(fail, fail);
    ret = xqc_engine_packet_process(engine, pkt, len,
                                    (struct sockaddr *)&local, sizeof(local),
                                    (struct sockaddr *)&peer, sizeof(peer),
                                    xqc_monotonic_timestamp(), NULL);
    xqc_test_rt_fail(0, 0);
    return ret;
}

#ifdef XQC_COMPAT_GENERATE_SR_PKT
static int
xqc_test_rt_deprecated_reset(xqc_engine_t *engine, xqc_cid_t *cid, int fail)
{
    int ret;

    xqc_test_rt_fail(fail, fail);
    ret = xqc_is_deprecated_reset_packet(cid, xqc_test_rt_sr_pkt,
                                         xqc_test_rt_sr_len,
                                         engine->config->reset_token_key,
                                         engine->config->reset_token_keylen);
    xqc_test_rt_fail(0, 0);
    return ret;
}
#endif

void
xqc_test_reset_token_stateless_reset_failure(void)
{
    unsigned char           derived[XQC_STATELESS_RESET_TOKENLEN];
    unsigned char           pkt[64];
    xqc_engine_t           *engine;
    xqc_cid_t               cid;

    engine = test_create_engine_server();
    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
    engine->transport_cbs.stateless_reset = xqc_test_rt_stateless_reset;

    /* a short header packet, to a connection ID the server does not know */
    xqc_test_rt_cid(&cid, engine->config->cid_len, 0x81);
    xqc_test_rt_derive(engine, &cid, derived);
    memset(pkt, 0x5c, sizeof(pkt));
    pkt[0] = 0x40;
    memcpy(pkt + 1, cid.cid_buf, cid.cid_len);

    /* no token: no stateless reset */
    xqc_test_rt_sr_count = 0;
    CU_ASSERT(xqc_test_rt_unknown_packet(engine, pkt, sizeof(pkt), 1)
              == -XQC_ECONN_NFOUND);
    CU_ASSERT(xqc_test_rt_sr_count == 0);

    /* sent once a token can be made, ending with it */
    CU_ASSERT(xqc_test_rt_unknown_packet(engine, pkt, sizeof(pkt), 0)
              == -XQC_ECONN_NFOUND);
    CU_ASSERT_FATAL(xqc_test_rt_sr_count == 1);
    CU_ASSERT_FATAL(xqc_test_rt_sr_len >= XQC_STATELESS_RESET_PKT_MIN_LEN);
    CU_ASSERT(memcmp(xqc_test_rt_sr_pkt + xqc_test_rt_sr_len
                     - XQC_STATELESS_RESET_TOKENLEN, derived,
                     XQC_STATELESS_RESET_TOKENLEN) == 0);

#ifdef XQC_COMPAT_GENERATE_SR_PKT
    /*
     * That reset is of the deprecated kind, recognised by its token. Without
     * a token of our own, neither it nor one with a zeroed token matches.
     */
    CU_ASSERT(xqc_test_rt_deprecated_reset(engine, &cid, 0) == 1);
    CU_ASSERT(xqc_test_rt_deprecated_reset(engine, &cid, 1) == 0);
    memset(xqc_test_rt_sr_pkt + xqc_test_rt_sr_len
           - XQC_STATELESS_RESET_TOKENLEN, 0, XQC_STATELESS_RESET_TOKENLEN);
    CU_ASSERT(xqc_test_rt_deprecated_reset(engine, &cid, 1) == 0);
#endif

    xqc_engine_destroy(engine);
}

#else

/* each needs the linker's --wrap (see tests/CMakeLists.txt) */

void
xqc_test_reset_token_alloc_failure(void)
{
}

void
xqc_test_reset_token_crypto_failure(void)
{
}

void
xqc_test_reset_token_new_cid_failure(void)
{
}

void
xqc_test_reset_token_server_failure(void)
{
}

void
xqc_test_reset_token_stateless_reset_failure(void)
{
}

#endif
