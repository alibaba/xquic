# MoQT Draft-22 Architecture Decisions

The [protocol specification][protocol] owns fields, entity mappings, and
lifetimes. This document records architectural tradeoffs and design entry
points. The [capability table][completeness] owns implementation status.

## Module and Compatibility Boundaries

Use separate `include/moq/xqc_moqt.h` and `moq/moqt/`, named by
responsibility rather than draft number. The draft-05 stream/message model,
public by-value structures, and media/FEC fields cannot acquire new semantics
through limited extension while preserving ABI. Retain the legacy path at the
cost of two wire state machines. Evolve later drafts in the same module,
keeping version constants immutable.

Clients explicitly choose one ALPN. Servers register both and dispatch by
actual ALPN, without new public connect/TLS arguments or automatic client
fallback. Isolate resumption contexts and default to 1-RTT. Implement new
resumption under its dedicated design; never import legacy fast-RTT state.

## Reuse and Ownership

- Stream binds native transport and owns one RX/TX pair. Request embeds only
  request state in a REQUEST Stream. Separate application Request handles from
  transport callback Stream contexts.
- Session owns Subscription/Fetch. Request only references delivery; physical
  closure is not delivery completion. Fill reuses Fetch, associated with its
  Subscription through triggering ID and parameter snapshot.
- Track shares a binary Full Track Name. Group/Subgroup retain active
  cross-stream summaries only. Object is borrowed, without an Object tree or
  payload history cache. Full historical validation remains incomplete.
- Reuse byte views, parameter layout, var_buf/list_buf, vi64, timers, and QUIC.
  Extend only necessary members. vi64 does not replace QUIC varint, and
  parameter values do not use KVP parity encoding. Separate codec readers and
  writers; field failure returns immediately without cross-layer error state.
- Retain active references during callbacks, releasing after transport
  callbacks/current stack. Borrowed bytes cannot outlive a callback.
  Asynchronous completion after cancel only releases resources; it cannot
  resurrect a request. Notify each terminal state at most once.

## Protocol, Application, and Relay

The library owns messages, stream association, delivery, and budgets, reusing
native reliable reset/recovery. Applications supply identity/authorization,
Track metadata, and historical data/existence; missing cache is not
nonexistence. Basic backpressure/cancellation accompany features. Advanced
optimization cannot exchange bounded queues for apparent interoperability.

Relay separately owns cross-session routing, source sets, aggregation, fanout,
and caches through public endpoint APIs. Each hop has independent Request
IDs, aliases, and authorization. Media packaging and interop runner/image glue
belong to application testing, outside protocol state machines.

## Canonical Design Entry Points

| Design | Single maintained location |
| --- | --- |
| Layers and bounded defaults | [Implementation outline](../../../spec/moqt/moqt-protocol.md#rebuild-review) |
| Entities, field mappings, identity, references | [Entity design](../../../spec/moqt/moqt-protocol.md#entity-structure-design) |
| DONE, late data, cancellation, deadlines | [Delivery lifecycle](../../../spec/moqt/moqt-protocol.md#delivery-lifecycle) |
| Requests, candidate authorization, updates | [Request lifecycle](../../../spec/moqt/moqt-protocol.md#request-lifecycle) |
| FETCH history and Fill snapshots | [FETCH](../../../spec/moqt/moqt-protocol.md#fetch-decoding-history), [Fill](../../../spec/moqt/moqt-protocol.md#fill-design) |
| Namespace notifications/request independence | [Discovery/query](../../../spec/moqt/moqt-protocol.md#namespace-state-boundaries) |
| Priority, ordering, queue selection | [Scheduling](../../../spec/moqt/moqt-protocol.md#priority-scheduling-design) |
| Resumption, replay, rejection recovery | [0-RTT](../../../spec/moqt/moqt-protocol.md#moqt-0rtt-negotiation) |
| Relay state/cross-session reclamation | [Relay](../../../spec/moqt/moqt-relay.md#relay-integration) |

## Unresolved Design and Validation

TRACK_STATUS_OK/EXPIRES and SUBSCRIBE_TRACKS Location/Fill inheritance contain
conflicting draft text. Retain an explicit sending subset and independent
vectors; peer tolerance is not specification interpretation. Historical
consistency beyond active summaries, WT adapter lifetimes, Relay cache
transactions, media profiles, and other gaps remain explicit in the capability
table. Reorganizing documents cannot mark them complete.

Risks include ABI/ALPN isolation, delta contexts, multi-stream callback
reentrancy/cancellation races, data-source existence knowledge, and exhausted
budgets. The specification defines paired acceptance; record independent
interop separately from local two-endpoint tests. If exact draft text cannot
resolve a difference, retain byte vectors/provenance and clarify design before
changing public behavior.

[protocol]: ../../../spec/moqt/moqt-protocol.md
[completeness]: ../../../spec/moqt/moqt-protocol.md#functional-completeness
