# XQUIC Architecture Map

This document is a navigation aid and boundary description. Detailed behavior
belongs in module documentation, public headers, tests, and the protocol
specifications that XQUIC implements.

See the
[project instructions](PROJECT_INSTRUCTIONS.md) for related project contracts
and the [development pipeline](../pipelines/dev-pipeline.md) for the execution
order.

## Repository Map

- `include/xquic/`: public XQUIC and HTTP/3 API.
- `src/common/`: shared data structures, memory helpers, logging, and utilities.
- `src/transport/`: QUIC engine, connections, streams, packets, recovery, and
  transport extensions.
- `src/tls/`: TLS integration, with backend-specific adapters under
  `src/tls/boringssl/` and `src/tls/babassl/`.
- `src/http3/`: HTTP/3 connection and stream behavior.
- `src/http3/frame/`: HTTP/3 frame encoding and parsing.
- `src/http3/qpack/`: QPACK state, encoding, and decoding.
- `src/congestion_control/`: congestion-control implementations.
- `tests/unittest/`: CUnit regression and unit tests.
- `tests/`, `demo/`, and `mini/`: executable test and example applications.
- `moq/` and `include/moq/`: optional Media over QUIC support, enabled with
  `XQC_ENABLE_MOQ`.
- `cmake/` and the root `CMakeLists.txt`: build graph and dependency discovery.
- `scripts/`: repository-wide build, test, interoperability, and analysis tools.

## Protocol Stack and Specifications

### HTTP/3 Stack

The logical protocol stack for HTTP/3 is:

```text
application protocol    HTTP/3, QPACK, HTTP priority
transport-security      QUIC-TLS
core transport          QUIC Transport, Recovery, QUIC DATAGRAM, Multipath
network                 UDP/IP
```

### MoQ Stack

The logical protocol stack for MoQ is:

```text
application protocol    LOC / MSF
media transport         MoQT
transport-security      QUIC-TLS
core transport          QUIC Transport, Recovery, QUIC DATAGRAM, Multipath
network                 UDP/IP
```

These views describe protocol relationships, not compile-time dependency
direction. The published standards below map only to capabilities represented
in the repository; they do not imply support for every RFC produced by the
QUIC or HTTP working groups.

### Published Standards

| Protocol or capability | Governing specification | Primary implementation |
|------------------------|-------------------------|------------------------|
| QUIC invariants | [RFC 8999: Version-Independent Properties of QUIC](https://www.rfc-editor.org/rfc/rfc8999.html) | QUIC packet and version processing in `src/transport/` |
| QUIC Transport | [RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000.html) | `src/transport/` |
| Recovery | [RFC 9002: QUIC Loss Detection and Congestion Control](https://www.rfc-editor.org/rfc/rfc9002.html) | `src/transport/xqc_send_ctl.*` and `src/congestion_control/` |
| QUIC-TLS | [RFC 9001: Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001.html) | `src/tls/` |
| HTTP/3 | [RFC 9114: HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html) | `src/http3/` and `src/http3/frame/` |
| QPACK | [RFC 9204: QPACK: Field Compression for HTTP/3](https://www.rfc-editor.org/rfc/rfc9204.html) | `src/http3/qpack/` |
| HTTP priority | [RFC 9218: Extensible Prioritization Scheme for HTTP](https://www.rfc-editor.org/rfc/rfc9218.html) | HTTP/3 request and stream priority handling in `src/http3/` |
| QUIC DATAGRAM | [RFC 9221: An Unreliable Datagram Extension to QUIC](https://www.rfc-editor.org/rfc/rfc9221.html) | `src/transport/xqc_datagram.*` |

### Work-in-Progress Standards

Internet-Drafts can change or be replaced. These version-independent
Datatracker links resolve to the current revision:

| Protocol or capability | Governing draft | Primary implementation |
|------------------------|-----------------|------------------------|
| Multipath QUIC | [Managing multiple paths for a QUIC connection](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/) | `src/transport/xqc_multipath.*`, `src/transport/scheduler/`, and `src/transport/reinjection_control/` |
| MoQT | [Media over QUIC Transport](https://datatracker.ietf.org/doc/draft-ietf-moq-transport/) | Optional `moq/` and `include/moq/`, enabled with `XQC_ENABLE_MOQ` |

## Dependency Direction

The intended high-level dependency direction is:

```text
applications and tests
        |
public API (include/xquic)
        |
HTTP/3 and optional application protocols
        |
QUIC transport
        |
TLS adapters, congestion control, and common utilities
```

Public headers must not depend on test or demo code. Core QUIC and HTTP/3 code
must not depend on the optional MoQ module. Backend-specific TLS behavior stays
behind the TLS integration layer.

## Protocol Invariants

- Wire behavior is governed by the applicable IETF RFC or draft.
- Normative requirements take precedence over local implementation
  convenience.
- Protocol errors must use the most specific error code required by the
  governing specification.
- Unsupported extensions must follow the specification's negotiation and
  error-handling rules.
- A protocol fix requires a regression test at the lowest layer that can
  observe the invariant reliably.

These boundaries are initially documented rather than mechanically enforced.
When the same class of violation recurs, promote the invariant into a test,
lint, or structural check.
