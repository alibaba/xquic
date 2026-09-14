# Design

Use the normal demo engine and standard h3 ALPN. WebTransport registers
its existing ALPN stream and datagram callbacks and wraps existing H3
connection/request callbacks. It preserves application engine, connection,
request and transport user data. Remove the generic H3 extension registration,
callback table, connection state and stream state.

Keep the QUIC engine and H3 context implementation unchanged. A WT-owned
registration allocation embeds the ordinary H3 context as its first member,
followed by WT configuration, so existing ALPN cleanup owns one allocation.
Each WT connection copies the configuration and original application callbacks.
Teardown does not borrow engine registration storage.

H3 exposes `xqc_h3_conn_set_setting()` for registering additional local
SETTINGS by identifier and value. H3 owns copied entries; repeated identifiers
update their value before encoding. Once the SETTINGS frame is queued,
registration fails without changing the advertised values. Core H3/QPACK
settings retain their existing configuration path. WT registers its three
draft-07 settings through this API. The frame writer has one entry point,
`xqc_h3_frm_write_settings()`.

Other H3 changes are limited to callbacks for unknown peer settings and SETTINGS
completion, and declaration of its existing input parser for prefix replay.
WT supplies callback data. The H3 SETTINGS callbacks are not a protocol
registration framework.

Keep stream demultiplexing in `src/webtransport/xqc_webtransport_h3_stream.c`.
The WT ALPN adapter owns prefix classification, buffering, pause/resume,
stream state and raw stream creation. It reads only the initial type before
classification, replays ordinary prefixes to H3, then delegates subsequent
ordinary events to the original H3 stream callbacks. WT streams stay with WT
callbacks. No WT state or dispatch callbacks remain in H3 stream objects.
An incomplete prefix is cleaned up on close. Detached WT streams never return
to HTTP parsing, and buffered FIN survives an EAGAIN retry.

Each WT connection owns its session registry and stream adapter list.
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
