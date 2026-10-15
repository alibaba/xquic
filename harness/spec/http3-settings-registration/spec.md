# HTTP/3 SETTINGS Registration Specification

This specification defines XQUIC's generic registry for additional HTTP/3
SETTINGS. It is independent from QUIC reliable stream reset and does not own
the semantics of any consuming extension.

## Scope and Authority

The governing sources are
[RFC 9114 Section 7.2.4](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4)
for the SETTINGS frame,
[Section 9](https://www.rfc-editor.org/rfc/rfc9114.html#section-9) for HTTP/3
extensions, and
[Section 11.2.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-11.2.2)
for setting identifier registration.

The registry provides initialization storage, serialization, single-send
timing, and one public batch receive callback for downstream protocols. Each
extension owns its identifiers, legal values, defaults, cross-setting
validation, 0-RTT compatibility, and enablement policy.

## Public Configuration Contract

The public declarations are in
[`include/xquic/xqc_http3.h`](../../../include/xquic/xqc_http3.h).
`xqc_h3_setting_t` is the shared identifier/value representation for built-in
and extension entries. Its fields are complete `uint64_t` values; varint
parsing state remains local to the parser. `xqc_h3_conn_settings_t` retains
the built-in typed fields and embeds `extern_settings` and its count. Both
local and peer configuration reuse this original connection settings type.
Core and extern configuration share the existing engine-default copy and
`h3_conn_init_settings` per-connection override lifecycle.

Applications must fully initialize standalone settings objects, for example
with `xqc_h3_conn_settings_t settings = {0}`, or copy an initialized object
before setting individual fields. The library initializes the object passed to
`h3_conn_init_settings`; the callback preserves its existing values. Maintain
the extern list through `xqc_h3_conn_settings_add_extern()` and do not assign
`extern_settings_count` directly.

`xqc_h3_conn_settings_add_extern()` adds or replaces a pair in a settings
object. A second call with the same identifier updates the value without consuming a
new slot. A settings object can hold at most 16 distinct additional settings,
and both fields must fit in a QUIC 62-bit variable-length integer. The helper
returns `XQC_OK`, or `-XQC_EPARAM` for a null object, invalid value, full array,
reserved identifier `0x00`, HTTP/2-reserved identifier `0x02` through `0x05`,
or core identifier `0x01`, `0x06`, or `0x07` that uses an existing typed field.

Applications can use the helper before installing engine defaults or from
`h3_conn_init_settings`, where only the supplied settings object can be
modified. Applications must not retain the callback's settings pointer. H3
validates the final object after the callback and before QPACK and SETTINGS
serialization. An invalid local configuration fails connection
initialization without emitting a partial SETTINGS frame.

When error logging is enabled, local validation reports the first failure:
the invalid count and limit, the overflowing core field and value, or the
extern entry index, identifier, and value. Duplicate identifiers also report
the previous entry index. Validation preserves the settings object and the
existing `-XQC_EPARAM` result; successful validation emits no error log.

The helper does not consult the IANA registry. Callers must not use reserved
identifier `0x00`. The grease-reserved series `0x1f * N + 0x21` can be used to
exercise unknown-setting handling but must not be assigned extension
semantics. The registry emits the three core XQUIC settings first and then
additional settings in registration order, with every identifier appearing
once.

SETTINGS is serialized once. The internal queued state prevents a second
encoding; transport `-XQC_EAGAIN` retries the existing send buffer and never
regenerates the frame from a possibly changed object.

## Public Receive Callback Contract

Core settings remain handled by the HTTP/3 connection. H3 buffers and parses
the complete SETTINGS payload into one bounded temporary array before notifying
the application. It rejects incomplete identifier or value varints,
HTTP/2-reserved identifiers, duplicate identifiers, and invalid core settings
before callback. The duplicate policy is an implementation choice permitted
by RFC 9114.

Receive calls may end inside the frame length, an identifier, or a value.
The frame parser preserves its varint context and appends payload bytes to the
SETTINGS buffer until the advertised frame length is complete. Only then does
the control stream call the entry parser. Its cursor is local to that complete
payload; no entry or callback is published while payload bytes are missing.
A final incomplete varint inside a fully received payload is a frame error,
not a request to wait for bytes from the next frame.

`xqc_h3_conn_callbacks_t.h3_conn_peer_extern_settings_notify` receives the
HTTP/3 connection, a borrowed read-only array of every non-core, non-GREASE setting
in wire order, its count, and the existing H3 connection user data. It runs
exactly once for each structurally valid peer SETTINGS, including when count
is zero. When count is zero, the pointer may be NULL and must not be
dereferenced. The array is valid only during the callback; an application that
needs it later copies the scalar pairs.

The callback returns one of three explicit results:

- accept, after which H3 publishes the received settings state;
- settings reject, which closes with `H3_SETTINGS_ERROR`; or
- internal failure, which closes with `H3_INTERNAL_ERROR`.

A handler consumes only identifiers it owns and ignores other unknown entries.
SETTINGS advertises unilateral capabilities or limits; it is not a generic
synchronized negotiation event. A settings reject publishes no application
capability, and a structurally invalid frame never invokes the callback.

RFC 9114 requires SETTINGS to be the first frame on each control stream and
allows only one SETTINGS frame per control stream. A sender MUST NOT repeat an
identifier. A receiver MAY treat a duplicate as `H3_SETTINGS_ERROR`; XQUIC
selects that policy uniformly before standard processing or application
notification. GREASE entries are ignored by H3 and are not delivered as
extension semantics.

After complete validation, H3 applies core settings, captures their fingerprint
in wire order, and compacts the extension entries in the same temporary array.
Only core values are applied to the peer configuration; its extern list stays
empty. Received extern entries are borrowed during the callback, with no
persistent copy. Reusing the original configuration type reserves the fixed
extern slots in both local and peer objects. The 4096-byte receive payload
limit bounds the temporary array to 32 KiB. Duplicate detection scans that
bounded array once per peer SETTINGS, preserving order without a second index.

Incomplete fields in a complete SETTINGS payload produce `H3_FRAME_ERROR`
(RFC 9114 Section 7.1). Reserved or duplicate identifiers and application
rejection produce `H3_SETTINGS_ERROR`. A second SETTINGS frame produces
`H3_FRAME_UNEXPECTED`. Empty SETTINGS completes normally, but zero-length frames
that require a varint field fail parsing before any zero-valued field is used.

The public settings and callback structures require applications and the
library to be rebuilt together. New entry types, extern fields, and APIs are
unconditional. The pre-existing `XQC_COMPAT_DUPLICATE` field guard is retained;
applications and the library must use matching compatibility configuration.

## WebTransport over HTTP/3 Dependency

[WebTransport over HTTP/3 draft-16](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16)
is the primary dependent protocol. Its binding uses the registry for these
settings:

| Setting | Identifier |
|---------|------------|
| `SETTINGS_ENABLE_CONNECT_PROTOCOL` | `0x08` |
| `SETTINGS_H3_DATAGRAM` | `0x33` |
| `SETTINGS_WT_ENABLED` | `0x2c7cf000` |
| `SETTINGS_WT_INITIAL_MAX_DATA` | `0x2b61` |
| `SETTINGS_WT_INITIAL_MAX_STREAMS_UNI` | `0x2b64` |
| `SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI` | `0x2b65` |

[Draft-16 Section 3.1](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-3.1)
requires the server to send the first three enablement settings with value 1;
the client sends HTTP/3 Datagram and its draft-specific WebTransport setting.
[RFC 9220](https://www.rfc-editor.org/rfc/rfc9220.html) defines Extended
CONNECT, and [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297.html) defines
HTTP/3 Datagram.
[Section 7.1](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-16#section-7.1)
uses version-specific `SETTINGS_WT_ENABLED` identifiers and requires a server
to receive the client's SETTINGS before processing WebTransport requests.
Those identifiers and rules belong to the WebTransport binding, not this
generic registry.

WebTransport draft-16 separately depends on reliable stream reset. The two
foundation capabilities do not call or configure each other.

## 0-RTT and Validation Contract

An extension using remembered server SETTINGS in 0-RTT owns the compatibility
decision required by RFC 9114 Section 7.2.4.2. If current settings cannot
safely preserve remembered non-default behavior or limits, the server must
reject early data rather than accept incompatible requests.

The registered tests in
[`tests/unittest/xqc_h3_test.c`](../../../tests/unittest/xqc_h3_test.c) cover
configuration add/update, capacity, varint bounds, reserved identifiers,
inheritance, encoding order, single-send timing, and local validation error
diagnostics with and without a logger.

Required validation also includes complete-varint rejection, duplicate policy,
zero-count and non-empty batch callbacks, no callback before full public
validation, callback error mapping, more than 16 received unknown settings,
real WebTransport identifiers, remembered 0-RTT settings, and endpoint
SETTINGS exchange. The downstream binding installs the public batch callback
and implements WebTransport validation. WebTransport conformance belongs to
that downstream specification and its coverage.

The `http3.core` endpoint cases cover an application registering settings with
multi-byte identifiers and values, complete peer batch delivery, successful
HTTP exchange after acceptance, and `H3_SETTINGS_ERROR` after application
rejection. The existing CI case runner discovers these registrations.
