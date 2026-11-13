# MoQT Draft-22 Implementation Outline

The [protocol specification][protocol] governs entities/lifetimes; the
[relay specification][relay] governs Relay. The [capability table][completeness]
is the sole status/gap/interop-dependency index. This outline repeats neither
completion percentages, historical steps, review conclusions, nor run results.

## Endpoint Dependencies

| Layer | Capabilities and dependencies |
| --- | --- |
| Codec/transport integration | Common vi64, framing, names/KVP, explicit version, Native QUIC ALPN |
| Session/Request | SETUP, directional credit, ID/response FIFO, authorization, updates, closure, budgets |
| Subscription/live delivery | Track/Subscription/Alias, Location/FORWARD, Datagram/Subgroup, shared summaries, completion |
| Historical delivery | Standalone FETCH, Fill snapshots/live concurrency; application Objects/existence |
| Discovery/query | Namespace publish/discover, suffix/DONE, prefix updates, Track enumeration/independent PUBLISH/SKIPPED, TRACK_STATUS |

This is implementation structure, not completion of every related rule.
Timeout-property overrides, full historical consistency, and TRACK_STATUS
parameter conflicts remain F17/F20/F26 gaps.

## Remaining Work

Numbers retain future dependency order, without replaying delivered steps.
Add only necessary state/interfaces, reusing Stream/Request/Subscription/Fetch
without speculative placeholder frameworks.

| Order | Capability | Dependencies and key acceptance |
| --- | --- | --- |
| 13 | Native QUIC pipelining/0-RTT | [Resumption][resumption]; accept/reject/no-cache, one retransmission owner, authorization timing, no resurrection |
| 14 | Nonzero Range Filters | [Filters][filters]; SetID AND/OR, replace/delete/limits, Fill snapshots, FETCH gaps |
| 15 | Token Aliases | [Cache][tokens]; directional accounting, same/cross-stream response dependencies, expiry/delete, reauthorization |
| 16 | Remaining prefix Track combinations | [Prefix subscriptions][tracks]; C10 endpoint prerequisites are implemented; independent-peer confirmation of disputed Location/Fill inheritance remains; nonzero filters follow item 14 |
| 17 | Protocol-rule validation gaps | Scope/query/restart, property-set replacement/Mandatory phases, original Subgroup first-Object overrides, Prior Gap/history, parameter allowlists/conflicts |
| 18 | Dynamic Groups/EXPIRES renewal | [Groups][groups], [parameters][parameters]; application creation, boundaries/delay, independent clocks; Relay aggregation separate |
| 19 | Padding, overload, deployment security | [Deployment][security]; independent cancellation, short-prefix/slow-peer budgets, hop authorization, safe logs |
| 20 | Pinned independent interop | [Catalog][interop]; runner/images, complete-Object oracle, media fixtures, independent peer evidence |

## Separate Scopes

The [Relay core change](../moqt-relay-core/proposal.md) delivers its independent
implementation and local three-node cases. Remaining acceptance below also
includes external runner integration and broader TLS/interop evidence.

- [ ] Relay: hop IDs/Aliases, upstream Established, rendezvous, source sets,
  fanout/mixed pause, total FETCH/Fill budget, malformed/slow-peer isolation,
  overlapping migration; positive/negative three-node tests with two
  publishers and two subscribers.
- [ ] C10 Relay integration: reuse endpoint St enumeration, source-instance
  identity, and independent Pc mappings. Verify three-node discovery when
  only the Namespace is known, including cancellation/authorization/skipping
  boundaries; record pinned runner results separately from local two-endpoint
  evidence.
- [ ] Relay extensions: cache keys/deadlines/replacement transactions, nonzero
  filters, dynamic-Group outstanding aggregation, each
  following endpoint dependencies and relay scope.
- [ ] WebTransport: CONNECT selection, URI, WT binding, MOQT SETUP, DATAGRAM,
  and isolation within one H3 connection; no inherited Native QUIC 0-RTT claim.
- [ ] Media/interop tooling: traceable versions/images/fixtures, real display,
  complete-Object oracle; separate evidence beyond the fixed 22-case catalog
  for FETCH/Fill, 0-RTT, and other capabilities.

## Delivery Acceptance

Each behavior needs positive/negative units and real two-endpoint cases for
visible effects; Relay uses three nodes. Run complete MoQ ON/OFF, legacy
regression, and applicable harness/format checks. Verify current-head MoQ
Matrix, both TLS unit/regression profiles, and at least 90% production delta
coverage. Mark unrun sanitizers, independent peers, and media combinations
as gaps; codec self-tests cannot imply success. Documentation-only changes
use document gates without presenting old coverage as new evidence.

Deliver remaining items as separate commits with a primary diff and user
review before the next item; CI does not replace review. Allocate test IDs
under repository rules at implementation time, not in design. Keep run
evidence in validation artifacts/reviews; the table records only current
capabilities/gaps. Retain this ongoing change until final acceptance.

[protocol]: ../../../spec/moqt/moqt-protocol.md
[relay]: ../../../spec/moqt/moqt-relay.md
[completeness]: ../../../spec/moqt/moqt-protocol.md#functional-completeness
[resumption]: ../../../spec/moqt/moqt-protocol.md#moqt-0rtt-negotiation
[filters]: ../../../spec/moqt/moqt-protocol.md#range-filter-design
[tokens]: ../../../spec/moqt/moqt-protocol.md#token-alias-design
[tracks]: ../../../spec/moqt/moqt-protocol.md#subscribe-tracks-design
[groups]: ../../../spec/moqt/moqt-protocol.md#dynamic-group-design
[parameters]: ../../../spec/moqt/moqt-protocol.md#parameter-context-and-renewal
[security]: ../../../spec/moqt/moqt-protocol.md#deployment-and-security
[interop]: ../../../spec/moqt/moqt-protocol.md#interop-acceptance
