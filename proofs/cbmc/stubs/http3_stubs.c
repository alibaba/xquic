/*
 * Stubs for the CBMC harnesses of the HTTP/3 and QPACK parsers.
 */
#include <stdint.h>
#include "src/http3/xqc_h3_conn.h"

xqc_int_t nondet_xqc_int(void);

/*
 * xqc_h3_conn_on_settings_entry_received() (src/http3/xqc_h3_conn.c) applies
 * one core setting to the connection and its QPACK state.  The SETTINGS
 * parser only reads its return value; the stub returns XQC_OK or an error
 * nondeterministically, so both of the parser's paths are explored.
 */
xqc_int_t
xqc_h3_conn_on_settings_entry_received(uint64_t identifier, uint64_t value,
                                       void *user_data)
{
    (void)identifier;
    (void)value;
    (void)user_data;
    xqc_int_t r = nondet_xqc_int();
    __CPROVER_assume(r == XQC_OK || r == -XQC_H3_SETTING_ERROR);
    return r;
}

/* only formats addresses for log lines (unreachable with XQC_DISABLE_LOG) */
const char *
xqc_conn_addr_str(xqc_connection_t *conn)
{
    (void)conn;
    return "";
}
