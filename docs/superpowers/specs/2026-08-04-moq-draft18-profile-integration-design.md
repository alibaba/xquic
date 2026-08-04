# MoQT Draft-18 Profile Integration Design

## Goal

Add `moqt-18` as a third ALPN-selected MoQ version while preserving the
existing draft-05 and draft-14 wire behavior. Port the proven Draft-18 codec,
request-lifecycle, and test assets from the reference checkout without merging
or rebasing its repository history.

The long-term boundary is:

```text
semantic operation
        |
version profile
        |
contextual wire resolution
        |
codec and stream-state transaction
```

The integration must not add scattered `version == 18` branches to the common
writer, decoder, handler, or media paths.

## Source and Target Boundaries

Target checkout:

```text
/Users/sy03/moq_support_multi_version/xquic-alpn-v2
```

Reference implementation:

```text
/Users/sy03/.config/superpowers/worktrees/xquic/moqt-draft18-complete
```

The reference checkout is an implementation source, not a commit source.
Draft-18-local codec modules and tests may be ported with attribution to their
origin. Common `session`, `stream`, `writer`, `handler`, demo, and public-header
changes must be adapted to the target profile architecture rather than copied
wholesale.

## Non-Goals

- Do not merge, rebase, or cherry-pick the reference branch.
- Do not replace draft-05 or draft-14 behavior with Draft-18 behavior.
- Do not change existing public struct layout unless an additive API cannot
  express the required behavior.
- Do not claim complete Draft-18 support for reference features that remain
  partial, including the complete object data plane, FETCH/TRACK_STATUS,
  WebTransport, 0-RTT, full relay policy, or external-peer interoperability.
- Do not make the common MoQ layer understand Draft-18 numeric wire values.

## Why the Existing Lookup Is Insufficient

Draft-05 and draft-14 can mostly resolve a message from:

```text
stream kind + wire type
```

Draft-18 reuses numeric values across stream contexts. Resolution requires:

```text
profile + QUIC direction + stream class + message position + wire type
```

For example, the same numeric value can identify a request-stream response or
a unidirectional stream header. A global message enum or a wire-type-only
codec table cannot represent this without collisions.

## Core Types

Introduce an internal semantic identifier that is independent of every draft's
wire values:

```c
typedef enum {
    XQC_MOQ_SEMANTIC_CLIENT_SETUP,
    XQC_MOQ_SEMANTIC_SERVER_SETUP,
    XQC_MOQ_SEMANTIC_SUBSCRIBE,
    XQC_MOQ_SEMANTIC_SUBSCRIBE_OK,
    XQC_MOQ_SEMANTIC_PUBLISH,
    XQC_MOQ_SEMANTIC_REQUEST_OK,
    XQC_MOQ_SEMANTIC_REQUEST_ERROR,
    XQC_MOQ_SEMANTIC_SUBGROUP_HEADER,
    XQC_MOQ_SEMANTIC_SUBGROUP_OBJECT,
    XQC_MOQ_SEMANTIC_GOAWAY,
} xqc_moq_semantic_id_t;
```

The complete enum will contain only implemented semantic families. Adding an
enum member does not imply that every profile supports it.

Define the contextual key used by profile resolution:

```c
typedef enum {
    XQC_MOQ_MESSAGE_FIRST,
    XQC_MOQ_MESSAGE_NEXT,
} xqc_moq_message_position_t;

typedef struct {
    xqc_moq_stream_direction_t direction;
    xqc_moq_stream_kind_t      stream_kind;
    xqc_moq_message_position_t position;
} xqc_moq_wire_context_t;
```

Resolution returns immutable metadata and must not mutate a stream:

```c
typedef struct {
    xqc_moq_semantic_id_t                  semantic;
    uint64_t                               wire_type;
    const xqc_moq_message_codec_entry_t   *codec;
    xqc_moq_stream_kind_t                  resolved_stream_kind;
    xqc_moq_message_position_t             next_position;
} xqc_moq_message_resolution_t;
```

## Profile Contract

Extend `xqc_moq_version_profile_t` with version-local operations:

```c
xqc_int_t (*resolve_inbound)(
    const xqc_moq_wire_context_t *context,
    uint64_t wire_type,
    xqc_moq_message_resolution_t *resolution);

xqc_int_t (*resolve_outbound)(
    const xqc_moq_wire_context_t *context,
    xqc_moq_semantic_id_t semantic,
    xqc_moq_message_resolution_t *resolution);

void (*commit_message)(
    xqc_moq_stream_t *stream,
    const xqc_moq_message_resolution_t *resolution);
```

Draft-05 and draft-14 use a default adapter backed by their existing control
and data codec tables. Draft-18 uses its contextual registry. Common code calls
only the profile operations and never branches on a draft number.

Unsupported semantic operations return `-XQC_EALPN_NOT_SUPPORTED` before
message or stream state is mutated.

## Transactional Writer

Replace the temporary-initializer lookup sequence with an explicit semantic
write:

```c
xqc_moq_write_semantic_message(session, stream, semantic, msg_base);
```

The required order is:

1. Snapshot the current wire context.
2. Resolve semantic ID to wire type and codec without mutation.
3. Initialize and validate the message with the resolved codec.
4. Encode and submit the transport write.
5. Commit stream class and message position only after success.

Allocation, encoding, validation, and transport-write failures leave the
stream context byte-for-byte unchanged. This removes the current compatibility
shim that invokes a temporary initializer only to obtain a type before the
profile overwrites it.

## Transactional Decoder

Inbound decoding follows the corresponding order:

1. Read a wire type only when the current stream position requires one.
2. Ask the selected profile to resolve it in the current context.
3. Allocate through the returned codec.
4. Decode without committing stream classification or position.
5. Commit only after the complete message or stream header is accepted.
6. Destroy the temporary message and retain the old context on failure.

Draft-18 placement errors are mapped through the Draft-18 error namespace.
Draft-05 and draft-14 preserve their existing error mapping.

## Continuation State

Continuation is semantic state, not a fake wire type. Add a codec-owned resume
operation or named decode stage:

```c
typedef enum {
    XQC_MOQ_DECODE_MESSAGE_START,
    XQC_MOQ_DECODE_SUBGROUP_OBJECT,
} xqc_moq_decode_stage_t;
```

After a subgroup header succeeds, the profile commits
`XQC_MOQ_SEMANTIC_SUBGROUP_OBJECT` and the codec enters
`XQC_MOQ_DECODE_SUBGROUP_OBJECT`. No profile may assign a numeric
`cur_field_idx`, and no continuation-only pseudo-type participates in wire
lookup.

## Public ABI and Shared Object Model

Keep the existing public superset message structures for source and ABI
compatibility. Eliminate implicit `calloc` contracts through internal,
profile-local initializers that explicitly set:

- namespace representation and ownership;
- alias presence and invalid values;
- filter and forwarding defaults;
- parameter/property ownership;
- version-inapplicable fields.

New Draft-18 application behavior is exposed through additive functions and
opaque/internal state. Existing by-value callback structures are not enlarged.

## Draft-18 Module Port

Port and adapt these reference modules first because their behavior is
version-local:

```text
draft18/xqc_moq_d18_defs.*
draft18/xqc_moq_d18_registry.*
draft18/xqc_moq_d18_kv.*
draft18/xqc_moq_d18_setup.*
draft18/xqc_moq_d18_auth.*
draft18/xqc_moq_d18_params.*
draft18/xqc_moq_d18_properties.*
draft18/xqc_moq_d18_request.*
draft18/xqc_moq_d18_update.*
draft18/xqc_moq_d18_control.*
```

The target's `session`, `stream`, `writer`, `handler`, and profile modules own
integration. Large common-file diffs from the reference checkout are used as
behavioral evidence and test input, not copied as patches.

## Media Boundary

Add profile-local media operations:

```c
typedef struct {
    xqc_int_t (*validate_object)(...);
    xqc_int_t (*prepare_object)(...);
    xqc_int_t (*write_object)(...);
} xqc_moq_media_ops_t;
```

Validation occurs before media-location allocation, cursor advancement, buffer
allocation, or stream mutation. Draft-05 and draft-14 initially delegate to
their existing codecs. Draft-18 advertises only the data-plane capabilities
that have been ported and tested; other operations fail side-effect-free.

## E2E Harness Safety

Before adding a third ALPN profile, harden the current harness:

- Treat `MOQ_E2E_LOG_DIR` as a parent directory and create a unique
  `mktemp -d` child beneath it. Cleanup may remove only that owned child.
- Resolve each concurrent client's server SCID before waiting for server setup.
- Match `moq_setup_active` by that SCID, profile, and wire version so historical
  log records cannot satisfy the barrier.
- Preserve structured timeout diagnostics with predicate, PID, state, elapsed
  time, and deadline.

## Delivery Phases

### Phase 0: Protect the Existing Baseline

Fix E2E log ownership and SCID-specific barrier matching. Capture fresh v5/v14
unit, sanitizer, and five-scenario E2E evidence.

### Phase 1: Introduce Semantic Resolution

Add semantic IDs, wire contexts, resolution results, and profile hooks. Adapt
draft-05 and draft-14 without changing their encoded bytes or callbacks.

### Phase 2: Add Draft-18 Foundation

Register `moqt-18`, add its profile, contextual registry, exact error namespace,
SETUP, Key-Value Pairs, Request ID registry, and stream context. Keep unsupported
families explicit.

### Phase 3: Add Request Lifecycles

Port parameters, properties, authorization, SUBSCRIBE/PUBLISH, namespace,
SUBSCRIBE_TRACKS, REQUEST_OK/ERROR, REQUEST_UPDATE, PUBLISH_BLOCKED, and
PUBLISH_DONE using request-stream-local state.

### Phase 4: Add Control Lifecycles

Port control/request GOAWAY behavior, admission cutoffs, timeouts, callback
lifetime protection, and terminal stream cleanup.

### Phase 5: Add the Tested Data Plane

Port subgroup/datagram/object behavior only after profile-local media validation
and named continuation state exist. Do not advertise incomplete capabilities.

## Test Strategy

Every phase uses RED/GREEN tests and preserves older profiles.

Required unit coverage:

- semantic-to-wire mapping for every supported profile;
- contextual collisions for `0x05`, `0x10`, `0x50`, and `0x51`;
- first/next message placement and direction;
- successful commit and failure rollback for writer and decoder state;
- named subgroup continuation without numeric field-index knowledge;
- explicit initialization from nonzero-filled storage;
- unsupported media operations preserve every cursor;
- Draft-18 registry, SETUP, parameter, property, request, and control tests.

Required E2E coverage:

```text
moq-quic / moq-05 -> draft-05 media success
moq-14            -> draft-14 media success
moqt-18           -> Draft-18 SETUP and implemented request lifecycles
unknown ALPN      -> TLS ALPN rejection
v5/v14/v18        -> concurrent profile isolation
Draft-18          -> paired success and abnormal lifecycle cases
```

Golden vectors prove exact Draft-18 wire bytes. Self-interop proves local
client/server lifecycle behavior. External interoperability is reported only
for the exact tested commit and peer version.

## Acceptance Criteria

- No merge, rebase, or cherry-pick from the reference checkout.
- Common dispatch contains no new `version == 18` routing branches.
- Draft-05 and draft-14 wire vectors remain byte-identical.
- Draft-18 numeric collisions resolve by stream context.
- Stream state changes only after successful message completion/write.
- Public ABI remains compatible; new APIs are additive.
- Unsupported Draft-18 media paths fail before observable state mutation.
- All three ALPN profiles can be active concurrently without state crossover.
- Focused tests, complete MoQ CTest, sanitizers, and relevant E2E pairs pass.
- Remaining Draft-18 gaps are documented and not advertised as complete.

## Risks and Controls

- The central dispatch refactor can regress old drafts. Land the v5/v14 adapter
  and byte-golden tests before adding Draft-18.
- Reference fixes can be missed during adaptation. Maintain a source-to-target
  behavior matrix by Draft-18 module and test name.
- Dual lookup models add profile complexity. Keep the default v5/v14 adapter in
  one implementation and keep Draft-18 registry code version-local.
- Public superset structures remain technical debt. Explicit initialization
  removes correctness dependence on zero-filled allocation without breaking
  ABI.
- The three-version matrix increases runtime. Keep focused phase tests while
  retaining complete pre-submit validation gates.

## Reference Update Policy

Future reference changes are classified before porting:

1. Pure Draft-18 codec/registry/test changes may be adapted directly.
2. Session, stream, writer, handler, and demo changes are translated through
   profile and semantic interfaces.
3. QUIC-core fixes are evaluated independently and are not imported as part of
   MoQ version work.
4. Every port records the source commit and the target test that proves the
   behavior.
