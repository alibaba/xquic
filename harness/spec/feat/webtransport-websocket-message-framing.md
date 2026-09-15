# WebTransport-to-WebSocket Message Framing

## Scope

This application-layer protocol carries ordered binary and text messages in
each direction of a WebTransport bidirectional stream. Both endpoints enable
it only after application-level agreement. The selection mechanism is outside
this protocol and may use endpoint configuration or explicit negotiation. It
does not modify WebTransport or HTTP/3; other streams retain their existing
application semantics.

## Syntax

Each stream direction contains zero or more consecutive messages:

```text
Message = Version Flags Length Payload
```

| Field | Encoding |
|-------|----------|
| Version | 8-bit unsigned integer |
| Flags | 8-bit bit field |
| Length | QUIC variable-length integer, RFC 9000 Section 16 |
| Payload | `Length` octets |

Version 0 has these requirements:

- Version is `0x00`.
- Flags bit 0 is the message type: `0` is binary and `1` is text.
- Senders set Flags bits 1 through 7 to zero; receivers ignore them.
- Length is the number of octets in Payload. Zero is valid.
- Payload is opaque to this framing protocol.

Senders use the shortest valid Length encoding. Receivers accept every valid
1, 2, 4, or 8-octet QUIC variable-length integer encoding.

## Processing

Messages are concatenated without padding. Stream read and write boundaries
do not delimit messages. A receiver buffers incomplete fields and delivers a
message only after all Payload octets have arrived. One stream read can
complete zero, one, or multiple messages. Messages are delivered in stream
order.

FIN at a message boundary ends that stream direction. FIN within a message is
a protocol error. An unsupported Version is an error.

A binary message maps to WebSocket opcode `0x2`; a text message maps to opcode
`0x1`. WebSocket text validation and control-message mapping are outside the
scope of this protocol.
