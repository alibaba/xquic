/*
 * Stubs for the CBMC harnesses of the xquic transport parsers.
 *
 * Every stub here replaces code that runs only after a parser has already
 * decided the outcome of a frame.  None of them feeds data back into a
 * parser, so none of them can hide an out-of-bounds access, an overflow or
 * an undefined behaviour inside the parsers under test.
 */
#include <stddef.h>
#include <stdint.h>

struct xqc_connection_s;

/*
 * xqc_conn_closing() is called by XQC_CONN_ERR() right before a parser
 * returns its error.  It moves the connection state machine to CLOSING and
 * arms timers; nothing of that is read back by the parser, which returns
 * immediately afterwards.  Modelled as a no-op.
 */
void
xqc_conn_closing(struct xqc_connection_s *conn)
{
    (void)conn;
}

/*
 * xqc_conn_addr_str() only formats addresses for log lines.  The harnesses
 * are built with XQC_DISABLE_LOG, so this is normally unreachable; it is
 * kept so that a build with logging enabled still links.
 */
const char *
xqc_conn_addr_str(struct xqc_connection_s *conn)
{
    (void)conn;
    return "";
}
