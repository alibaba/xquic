/*
 * Stubs for the CBMC harnesses of the packet header parsers.
 *
 * Each replaces a lookup or a state change of the connection whose only
 * effect on the parser is its return value; the stubs return every value
 * the real function can return, so both of the parser's paths are explored.
 */
#include <stdint.h>
#include <stddef.h>
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_cid.h"
#include "src/tls/xqc_tls.h"

xqc_int_t nondet_xqc_int(void);
int nondet_int(void);
size_t nondet_size_t(void);
unsigned char nondet_uchar(void);

static xqc_cid_inner_t g_inner;

/* CID lookup in the connection's sets: found (non-NULL) or not (NULL) */
xqc_cid_inner_t *
xqc_cid_set_search_cid(xqc_cid_set_t *cid_set, xqc_cid_t *cid)
{
    (void)cid_set;
    (void)cid;
    return nondet_int() ? &g_inner : NULL;
}

/* version check against the engine's list: accepted or refused */
xqc_int_t
xqc_conn_version_check(xqc_connection_t *c, uint32_t version)
{
    (void)c;
    (void)version;
    return nondet_int() ? XQC_OK : -XQC_EPROTO;
}

/* DCID check of a short header packet: known or unknown */
xqc_int_t
xqc_conn_check_dcid(xqc_connection_t *conn, xqc_cid_t *dcid)
{
    (void)conn;
    (void)dcid;
    return nondet_int() ? XQC_OK : -XQC_ECONN_CID_NOT_FOUND;
}

/* state change of the client after a valid Retry; result only */
xqc_int_t
xqc_conn_on_recv_retry(xqc_connection_t *conn, xqc_cid_t *retry_scid)
{
    (void)conn;
    (void)retry_scid;
    return nondet_xqc_int();
}

/*
 * AEAD of the Retry pseudo-packet: reads pseudo[0, pseudo_len) like the real
 * function (so an out-of-bounds pseudo-packet is still caught), then writes a
 * nondeterministic tag of at most tag_cap bytes.
 */
xqc_int_t
xqc_tls_cal_retry_integrity_tag(xqc_log_t *log, uint8_t *in, size_t in_len,
                                uint8_t *out, size_t max_out_len,
                                size_t *out_len, xqc_proto_version_t ver)
{
    (void)log;
    (void)ver;
    if (in_len > 0) {
        volatile uint8_t first = in[0], last = in[in_len - 1];
        (void)first;
        (void)last;
    }
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= max_out_len);
    for (size_t i = 0; i < n; i++) {
        out[i] = nondet_uchar();
    }
    *out_len = n;
    return nondet_int() ? XQC_OK : -XQC_TLS_INTERNAL;
}
