# Design

Use the normal demo engine and standard h3 ALPN. Register WebTransport
through a generic HTTP/3 extension boundary; do not replace application
engine, connection, request, or transport user data. HTTP/3 owns parsed
headers, stream dispatch, and generic settings transport. WebTransport owns
version-specific values, validation, session association, and capsules.

Keep the QUIC engine unchanged. Store the flat adapter configuration in the
H3 context allocation so the existing ALPN cleanup frees it. Each connection
owns copies of its adapter callbacks and WT configuration; connection and
stream teardown therefore does not borrow the engine's registration state.

Route CONNECT and session capsules through the existing request callback
table in the WT adapter. H3 request code stays unchanged. H3 additions are
limited to extension registration and private connection lifetime, generic
SETTINGS exchange, and raw stream dispatch required by draft-07 sections
3.1, 3.2, 4.1 and 4.2. WT stream classification must precede ordinary HTTP
frame parsing; its bidirectional prefix has no HTTP frame-length field.

Each H3 connection has private adapter state and a session registry.
Each WT stream has one underlying QUIC stream. Callbacks carry the original
application context. Session teardown detaches lookup state and keeps
callback data valid during final notification. Stream short-write results
count application payload only.

Sources:
- harness/spec/feat/webtransport.md
- harness/spec/feat/webtransport-server-api-spec.md
- draft-ietf-webtrans-http3-07 sections 3, 4, 5 and 6, for the Chrome
  compatibility mode only
- draft-ietf-webtrans-http3-16 section 3, for the unresolved draft-16 gate
- QUICHE quiche/quic/core/http/quic_spdy_session.cc and http_constants.h

The demo opts into WT, validates its endpoint and allowed browser origin,
and uses a local short-lived certificate with an explicitly supplied
certificate hash in the browser test page. It does not change global browser
certificate verification or system trust.

Use existing CUnit registration and scripts/validate.sh. Add unit tests for
normal and abnormal setup, session association, partial input/output and
teardown. Native integration and Chrome results must be reported separately.
Do not assign new legacy -x case IDs for the standalone browser harness.
