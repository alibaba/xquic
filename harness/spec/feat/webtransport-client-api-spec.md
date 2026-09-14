# WebTransport Native Client: Immutable XQUIC API Specification

The native HTTP/3 client API names, signatures, callback fields, ctx usage,
and lifecycle semantics below MUST remain unchanged for draft-07 and
draft-16.

```c
#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include <xquic/xqc_webtransport.h>
```

## 1. Engine and Context Initialization

```c
xqc_int_t xqc_wt_ctx_init(xqc_engine_t *engine,
    xqc_webtransport_dgram_callbacks_t *dgram_cbs,
    xqc_webtransport_session_callbacks_t *session_cbs,
    xqc_webtransport_stream_callbacks_t *stream_cbs);

xqc_int_t xqc_wt_engine_set_default_settings(xqc_engine_t *engine,
    const xqc_webtransport_conn_settings_t *settings);
```

The application MUST initialize WT before creating connections and configure
default settings before the first connection. XQUIC MUST copy the callback
tables and settings and preserve existing H3 callbacks and application
user data. WT initialization MUST NOT replace `xqc_engine_t.user_data`.

`NULL` settings select draft-07/16 support and one simultaneous session per
connection. `XQC_WEBTRANSPORT_DRAFT_VERSION_7` advertises only draft-07;
`XQC_WEBTRANSPORT_DRAFT_VERSION_16` advertises both versions and selects the
highest common version. Applications MUST use these enum constants, not
literal draft numbers.

Draft-16 configuration requires `max_sessions_count=1`; session pooling and
session-level flow control are not enabled. Missing draft-16 prerequisites
MUST cause rejection after version selection, without downgrading to
draft-07.

## 2. Connection Creation and ctx

```c
const xqc_cid_t *xqc_webtransport_connect(xqc_engine_t *engine,
    const xqc_conn_settings_t *conn_settings,
    const unsigned char *token, unsigned token_len, const char *server_host,
    int no_crypto_flag, const xqc_conn_ssl_config_t *conn_ssl_config,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    void *user_data);
```

The call creates the underlying connection using `h3` ALPN, enables QUIC
datagrams, and enables reliable reset when draft-16 is offered. Failure
returns `NULL`. The returned CID is borrowed; the caller MUST copy it into
application-owned storage. TLS verification remains controlled by the
supplied `xqc_conn_ssl_config_t`.

`user_data` is the application-owned connection ctx. XQUIC MUST preserve it
and pass the H3 connection's application data to session callbacks as
`h3c_user_data`. The application MUST retain this ctx through the final H3
connection-close callback, including all WT session-close callbacks.

## 3. Session Creation and Lifecycle

```c
xqc_wt_session_t *xqc_wt_client_open_session(xqc_h3_conn_t *h3_conn,
    const char *authority, const char *path, const char *origin, int *err);

xqc_int_t xqc_wt_session_close_with_error(xqc_wt_session_t *session,
    uint32_t error_code, const char *reason, size_t reason_len);
```

`xqc_wt_client_open_session` opens a pending session on an existing client
H3 connection. The authority MUST be nonempty and the path MUST begin with
`/`; Origin MAY be `NULL` for a native client. XQUIC MUST copy the request
strings before returning. CONNECT MUST be sent only after the handshake and
complete peer SETTINGS. Synchronous validation or resource failure returns
`NULL` and, when provided, stores the negative error in `err`. A non-`NULL`
result stores `XQC_OK` and identifies the created handle, not session
readiness. An immediate request-send failure can invoke the close callback
before the open call returns; callback state MUST be initialized beforehand.

The returned session is library-owned. Applications MUST wait for
`webtransport_session_create_notify` before creating data streams or sending
datagrams. This callback means a successful 2xx response; a rejected request
MUST NOT invoke it. `webtransport_session_close_notify` MUST also be
delivered for a rejected pending session.

Applications MUST retain session-specific state until that final callback
and discard the session handle when it returns. Local
`xqc_wt_session_close_with_error` copies the reason and initiates closure;
it does not immediately destroy the handle or transfer ownership to the
caller. Session and datagram callbacks use the H3 connection's application
ctx. Session closure MUST NOT free that shared ctx.

## 4. Stream Creation and ctx

```c
xqc_wt_bidistream_t *xqc_wt_session_create_bidi_stream(
    xqc_wt_session_t *session, void *user_data, int *err);

xqc_wt_unistream_t *xqc_wt_session_create_uni_stream(
    xqc_wt_session_t *session, void *user_data, int *err);
```

Stream creation requires an established, writable session. Failure returns
`NULL` and, when provided, stores the negative error in `err`; success stores
`XQC_OK`. Stream-create callbacks can run before these functions return.

A non-`NULL` `user_data` is the application-owned stream ctx passed to stream
callbacks. `NULL` selects the H3 connection's application ctx; incoming
streams use that connection ctx as well. XQUIC borrows these pointers and
MUST NOT free them. Applications MUST retain a stream ctx through its final
`wt_bidistream_close_notify` or `wt_unistream_close_notify` callback and MUST
NOT use the stream handle after that callback returns. A stream-close
callback MUST NOT free a shared connection ctx.

## 5. Session and Connection Queries

```c
xqc_webtransport_draft_version_t xqc_wt_session_get_draft_version(
    xqc_wt_session_t *session);
unsigned xqc_wt_session_get_response_status(xqc_wt_session_t *session);
xqc_h3_conn_t *xqc_wt_session_get_h3_conn(xqc_wt_session_t *session);
xqc_h3_conn_t *xqc_wt_conn_get_h3_conn(xqc_wt_conn_t *conn);
```

| Getter | Contract |
|---|---|
| `xqc_wt_session_get_draft_version` | Return the negotiated enum, or zero before selection. |
| `xqc_wt_session_get_response_status` | Return the HTTP response status, or zero before receipt. |
| `xqc_wt_session_get_h3_conn` | Return the session's borrowed H3 connection. |
| `xqc_wt_conn_get_h3_conn` | Return the WT connection's borrowed H3 connection. |

Getters MUST NOT transfer ownership or extend the underlying handle's
lifetime.

The shared session, stream, and datagram API inventory is listed in the
[server API specification](webtransport-server-api-spec.md#2-data-and-control-apis).
Client ctx ownership and lifecycle MUST follow this document.
The [native demo](../../../demo/webtransport.md) provides connection, echo,
rejection, and close commands.
