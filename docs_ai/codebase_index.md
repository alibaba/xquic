# Codebase Index

Source: project root

This document provides the file tree of the XQUIC codebase with annotations for each module's purpose. Use this to locate modules, understand ownership, and plan impact analysis.

## include/ -- Public API Headers

```
include/
  xquic/
    xquic.h              # Core transport API: engine, connection, stream, packet I/O
    xqc_http3.h          # HTTP/3 API: h3_conn, h3_request, QPACK settings
    xquic_typedef.h      # Forward declarations and platform-specific typedefs
    xqc_errno.h          # Error codes (XQC_OK, XQC_EAGAIN, CRYPTO_ERROR range, etc.)
    xqc_configure.h      # Auto-generated from xqc_configure.h.in by CMake (feature flags)
  moq/
    xqc_moq.h            # Media-over-QUIC experimental API
```

## src/transport/ -- QUIC Transport Layer (RFC 9000)

```
src/transport/
  xqc_engine.c/.h           # Engine lifecycle: create, destroy, packet dispatch, timer management
  xqc_conn.c/.h             # Connection state machine: handshake, migration, close, idle timeout
  xqc_client.c/.h           # Client-specific connection initiation
  xqc_cid.c/.h              # Connection ID management: generation, retirement, NEW_CONNECTION_ID
  xqc_stream.c/.h           # Bidirectional/unidirectional stream lifecycle and flow control
  xqc_datagram.c/.h         # QUIC Datagram extension (RFC 9221)
  xqc_packet.c/.h           # Packet number space management
  xqc_packet_in.c/.h        # Incoming packet processing and decryption
  xqc_packet_out.c/.h       # Outgoing packet assembly and encryption
  xqc_packet_parser.c/.h    # Long/short header parsing (Initial, Handshake, 0-RTT, 1-RTT)
  xqc_frame.c/.h            # Frame type definitions and dispatch
  xqc_frame_parser.c/.h     # Frame encoding/decoding (STREAM, ACK, CRYPTO, etc.)
  xqc_send_ctl.c/.h         # Send controller: congestion window, loss detection (RFC 9002)
  xqc_send_queue.c/.h       # Packet send queue management
  xqc_recv_record.c/.h      # Receive record for ACK generation
  xqc_recv_timestamps_info.c/.h  # ACK timestamp extension
  xqc_pacing.c/.h           # Packet pacing for smooth sending
  xqc_timer.c/.h            # Timer wheel: idle, loss detection, PTO, ACK delay
  xqc_transport_params.c/.h # Transport parameter encoding/decoding
  xqc_multipath.c/.h        # Multipath QUIC (draft-ietf-quic-multipath)
  xqc_reinjection.c/.h      # Packet reinjection framework for multipath
  xqc_quic_lb.c             # QUIC-LB server ID encoding (draft-ietf-quic-load-balancers)
  xqc_defs.c/.h             # Transport-layer constants and defaults
  xqc_utils.c/.h            # Transport utility functions

  scheduler/                 # Multipath packet scheduler strategies
    xqc_scheduler_common.c/.h      # Scheduler interface and common logic
    xqc_scheduler_minrtt.c/.h      # Min-RTT scheduler: prefer lowest latency path
    xqc_scheduler_backup.c/.h      # Backup scheduler: primary/backup path model
    xqc_scheduler_backup_fec.c/.h  # Backup scheduler with FEC integration
    xqc_scheduler_rap.c/.h         # Redundant ACK path scheduler
    xqc_scheduler_interop.c/.h     # Interop scheduler (enabled by XQC_ENABLE_MP_INTEROP)

  reinjection_control/       # Multipath packet reinjection strategies
    xqc_reinj_default.c/.h   # Default reinjection policy
    xqc_reinj_deadline.c/.h  # Deadline-based reinjection
    xqc_reinj_dgram.c/.h     # Datagram reinjection

  fec_schemes/               # Forward Error Correction (enabled by XQC_ENABLE_FEC)
    xqc_galois_calculation.c/.h   # Galois field arithmetic for Reed-Solomon
    xqc_xor.c/.h                  # XOR-based FEC scheme (XQC_ENABLE_XOR)
    xqc_reed_solomon.c/.h        # Reed-Solomon FEC scheme (XQC_ENABLE_RSC)
    xqc_packet_mask.c/.h         # Packet mask FEC scheme (XQC_ENABLE_PKM)
    xqc_packet_mask_value.h      # Pre-computed mask values
  xqc_fec.c/.h              # FEC framework integration
  xqc_fec_scheme.c/.h       # FEC scheme registration and dispatch
```

## src/http3/ -- HTTP/3 Layer (RFC 9114)

```
src/http3/
  xqc_h3_conn.c/.h          # HTTP/3 connection: settings, control stream, GOAWAY
  xqc_h3_stream.c/.h        # HTTP/3 stream types: request, control, push, encoder, decoder
  xqc_h3_request.c/.h       # HTTP/3 request lifecycle: send/receive headers and body
  xqc_h3_header.c/.h        # HTTP header processing and pseudo-header validation
  xqc_h3_ctx.c/.h           # HTTP/3 context: application-layer protocol negotiation (ALPN)
  xqc_h3_defs.c/.h          # HTTP/3 constants, error codes, frame types
  xqc_h3_ext_dgram.c/.h     # HTTP/3 Datagram extension (RFC 9297)
  xqc_h3_ext_bytestream.c/.h # HTTP/3 bytestream extension

  frame/
    xqc_h3_frame.c/.h       # HTTP/3 frame parsing: DATA, HEADERS, SETTINGS, GOAWAY, etc.
    xqc_h3_frame_defs.h     # Frame type constants

  qpack/                     # QPACK header compression (RFC 9204)
    xqc_qpack.c/.h          # QPACK encoder/decoder orchestration
    xqc_encoder.c/.h        # QPACK encoder: encode header fields
    xqc_decoder.c/.h        # QPACK decoder: decode header fields
    xqc_ins.c/.h            # QPACK instructions: insert, duplicate, set capacity
    xqc_rep.c/.h            # QPACK representations: indexed, literal, post-base
    xqc_prefixed_int.c/.h   # QPACK prefixed integer encoding/decoding
    xqc_prefixed_str.c/.h   # QPACK prefixed string (Huffman) encoding/decoding
    xqc_qpack_defs.h        # QPACK constants
    stable/
      xqc_stable.c/.h       # QPACK static table (RFC 9204 Appendix A)
    dtable/
      xqc_dtable.c/.h       # QPACK dynamic table: insert, evict, lookup
```

## src/tls/ -- TLS 1.3 Integration (RFC 9001)

```
src/tls/
  xqc_tls.c/.h              # TLS handshake state machine, QUIC-TLS interface
  xqc_tls_ctx.c/.h          # TLS context: certificate, session ticket, ALPN
  xqc_crypto.c/.h           # QUIC packet protection: header protection, AEAD encrypt/decrypt
  xqc_hkdf.c/.h             # HKDF key derivation for Initial/Handshake/1-RTT secrets
  xqc_null_crypto.c          # Null crypto for testing (no encryption)
  xqc_ssl_if.h              # SSL backend abstraction interface
  xqc_ssl_cbs.h             # SSL callback definitions
  xqc_tls_common.h          # Shared TLS definitions
  xqc_tls_defs.h            # TLS constants

  boringssl/                 # BoringSSL backend implementation
    xqc_hkdf_impl.c         # HKDF via BoringSSL EVP API
    xqc_crypto_impl.c       # AEAD/HP via BoringSSL EVP_AEAD/EVP_CIPHER
    xqc_ssl_if_impl.c       # SSL_CTX/SSL lifecycle via BoringSSL
    xqc_aead_impl.h         # BoringSSL AEAD algorithm mapping

  babassl/                   # BabaSSL (Tongsuo) backend implementation
    xqc_hkdf_impl.c         # HKDF via BabaSSL EVP API
    xqc_crypto_impl.c       # AEAD/HP via BabaSSL EVP API
    xqc_ssl_if_impl.c       # SSL_CTX/SSL lifecycle via BabaSSL
    xqc_aead_impl.h         # BabaSSL AEAD algorithm mapping
```

## src/congestion_control/ -- Congestion Control (Pluggable)

```
src/congestion_control/
  xqc_cubic.c/.h           # Cubic congestion control (default, always compiled)
  xqc_bbr.c/.h             # BBRv1 congestion control (always compiled)
  xqc_bbr2.c/.h            # BBRv2 congestion control (XQC_ENABLE_BBR2)
  xqc_new_reno.c/.h        # NewReno congestion control (XQC_ENABLE_RENO)
  xqc_copa.c/.h            # Copa congestion control (XQC_ENABLE_COPA)
  xqc_unlimited_cc.c/.h    # Unlimited CC for testing (XQC_ENABLE_UNLIMITED)
  xqc_sample.c/.h          # RTT/bandwidth sampling (shared by all CC algorithms)
  xqc_window_filter.c/.h   # Min/max window filter (shared by BBR/BBR2)
  xqc_bbr_common.h         # Shared definitions for BBR variants
```

## src/common/ -- Common Utilities

```
src/common/
  xqc_log.c/.h              # Logging framework with configurable levels
  xqc_log_event_callback.c/.h  # Event-based log callback (qlog support)
  xqc_random.c/.h           # Cryptographic random number generation
  xqc_str.c/.h              # String utilities (xqc_str_t)
  xqc_time.c/.h             # Monotonic timestamp utilities
  xqc_common.h              # Common includes and macros
  xqc_common_inc.h          # Master include for internal modules
  xqc_config.h              # Internal compile-time configuration
  xqc_malloc.h              # Memory allocation wrappers
  xqc_memory_pool.h         # Pool allocator
  xqc_algorithm.h           # Generic algorithm helpers (min, max, clamp)
  xqc_array.h               # Dynamic array
  xqc_buf.h                 # Buffer management
  xqc_fifo.h                # FIFO queue
  xqc_hash.h                # Hash function
  xqc_id_hash.h             # Integer-keyed hash table
  xqc_cid_hash.h            # CID-keyed hash table
  xqc_str_hash.h            # String-keyed hash table
  xqc_list.h                # Intrusive doubly-linked list
  xqc_queue.h               # Queue macros
  xqc_priority_q.h          # Priority queue (min-heap)
  xqc_rbtree.h              # Red-black tree
  xqc_siphash.h             # SipHash for hash table randomization
  xqc_object_manager.h      # Object pool manager

  utils/
    huffman/
      xqc_huffman.c/.h      # Huffman codec (QPACK/HPACK)
      xqc_huffman_code.c/.h  # Huffman code table
    vint/
      xqc_variable_len_int.c/.h    # QUIC variable-length integer encoding
      xqc_discrete_int_parser.c/.h  # Discrete integer parser
    ringarray/
      xqc_ring_array.c/.h   # Fixed-size ring buffer (array-based)
    ringmem/
      xqc_ring_mem.c/.h     # Ring memory allocator
    2d_hash/
      xqc_2d_hash_table.c/.h # Two-dimensional hash table
    var_buf/
      xqc_var_buf.c/.h      # Variable-length buffer with auto-resize
```

## tests/ -- Test Code

```
tests/
  test_client.c             # Integration test client (used by case_test.sh)
  test_server.c             # Integration test server (used by case_test.sh)
  getopt.c/.h               # Portable getopt for test binaries
  platform.h                # Platform abstraction for tests

  unittest/
    main.c                  # CUnit test runner entry point
    xqc_random_test.c/.h    # Random number generation tests
    xqc_pq_test.c/.h        # Priority queue tests
    xqc_common_test.c/.h    # Common utilities tests
    xqc_conn_test.c/.h      # Connection tests
    xqc_engine_test.c/.h    # Engine tests
    xqc_vint_test.c/.h      # Variable-length integer tests
    xqc_packet_test.c/.h    # Packet parsing tests
    xqc_recv_record_test.c/.h   # Receive record tests
    xqc_stream_frame_test.c/.h  # Stream frame tests
    xqc_process_frame_test.c/.h # Frame processing tests
    xqc_tp_test.c/.h        # Transport parameters tests
    xqc_tls_test.c/.h       # TLS integration tests
    xqc_crypto_test.c/.h    # Crypto operations tests
    xqc_crypto_frame_test.c/.h  # CRYPTO frame tests
    xqc_cid_test.c/.h       # Connection ID tests
    xqc_id_hash_test.c/.h   # ID hash table tests
    xqc_retry_test.c/.h     # Retry mechanism tests
    xqc_send_ctl_test.c/.h  # Send controller tests
    xqc_vn_test.c/.h        # Version negotiation tests
    xqc_frame_type_bit_test.c/.h  # Frame type bitmap tests
    xqc_ack_with_timestamp_test.c/.h  # ACK timestamp tests
    xqc_reno_test.c/.h      # NewReno CC tests
    xqc_cubic_test.c/.h     # Cubic CC tests
    xqc_datagram_test.c/.h  # Datagram tests
    xqc_h3_test.c/.h        # HTTP/3 tests
    xqc_h3_ext_test.c/.h    # HTTP/3 extension tests
    xqc_stable_test.c/.h    # QPACK static table tests
    xqc_dtable_test.c/.h    # QPACK dynamic table tests
    xqc_encoder_test.c/.h   # QPACK encoder tests
    xqc_qpack_test.c/.h     # QPACK integration tests
    xqc_prefixed_str_test.c/.h  # QPACK prefixed string tests
    xqc_fec_test.c/.h       # FEC framework tests
    xqc_fec_scheme_test.c/.h    # FEC scheme tests
    xqc_galois_test.c/.h    # Galois field tests

    utils/
      xqc_2d_hash_table_test.c/.h  # 2D hash table tests
      xqc_ring_array_test.c/.h     # Ring array tests
      xqc_ring_mem_test.c/.h       # Ring memory tests
      xqc_huffman_test.c/.h        # Huffman codec tests
```

## demo/ -- Demo Applications

```
demo/
  demo_client.c              # Full-featured QUIC client demo
  demo_server.c              # Full-featured QUIC server demo
  xqc_hq_ctx.c/.h           # HQ (HTTP/0.9-over-QUIC) context for interop testing
  xqc_hq_conn.c/.h          # HQ connection callbacks
  xqc_hq_request.c/.h       # HQ request callbacks
  xqc_hq_defs.h             # HQ definitions
  xqc_hq.h                  # HQ master include
  common.h                  # Shared definitions for demo programs
  CMakeLists.txt             # Build config for demo targets
```

## mini/ -- Minimal Example Applications

```
mini/
  mini_client.c/.h           # Minimal QUIC client (simplest usage example)
  mini_client_cb.c/.h        # Minimal client callbacks
  mini_server.c/.h           # Minimal QUIC server
  mini_server_cb.c/.h        # Minimal server callbacks
  common.c/.h                # Shared utilities for mini examples
  CMakeLists.txt             # Build config for mini targets
```

## scripts/ -- Build and Test Scripts

```
scripts/
  xquic_test.sh             # Full CI test runner (build both SSL backends + unit/case tests + gcov)
  case_test.sh               # Integration test cases (client-server interaction scenarios)
  xquic.lds                  # Linux linker version script (symbol visibility)
  qlog_parser.py             # QLOG event log parser utility
  goal.sh                    # Background goal launcher (harness tool)
  moq_scripts/
    moq_case_test.sh         # Media-over-QUIC test cases
```

## .claude/ -- Agent Workflow Configuration

```
.claude/
  commands/
    goal.md                  # Claude Code command wrapper for long-running goals
  skills/
    gh-pr-review/            # Source-backed GitHub PR review workflow
    gh-fix-ci/               # GitHub CI log diagnosis and smallest-fix workflow
    gh-address-comments/     # PR review comment triage and narrow edit workflow
    issue-to-branch/         # GitHub issue intake and scoped branch preparation
    xquic-safe-push/         # Branch, staging, commit, and remote push safety checks
```

## cmake/ -- CMake Modules

```
cmake/
  CMakeLists.txt             # CMake subdirectory config
  FindSSL.cmake              # Custom FindSSL for BoringSSL/BabaSSL detection
  FindCUnit.cmake            # CUnit discovery
  FindLibEvent.cmake         # libevent discovery
  ios.toolchain.cmake        # iOS cross-compilation toolchain
```

## Root Files

```
CMakeLists.txt               # Root build configuration (all targets, options, SSL backend selection)
xqc_configure.h.in           # Feature flag template (processed by CMake -> include/xquic/xqc_configure.h)
CONTRIBUTING.md              # Contribution guidelines
LICENSE                      # Apache 2.0 License
README.md                    # Project overview and quickstart
```
