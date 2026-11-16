# MoQT Draft-22 Implementation Outline

## Draft-22 Interoperability Case Plan

### Acceptance and counting

- XQUIC self-pair target: 40 client scenarios over Native QUIC and
  WebTransport, for 80/80 passing results. The latest report has 26
  scenarios and 52/52 results.
- aiomoqt target: aiomoqt's 20 default standard scenarios shared with XQUIC, in both client/relay
  directions and over both transports, for 80/80 passing results. Do not add
  unsupported scenarios to this denominator.
- Keep every scenario draft-22 only. Ignore draft-18 and draft-14 results.
- Complete one scenario at a time: run it against xquic-relay, then inspect the
  same scenario against available draft-22 peers. Fix XQUIC-caused wire or
  lifecycle mismatches. Mark a peer `SKIP` only when its unsupported behavior
  is confirmed by its capability list, an explicit protocol response, or its
  own TAP `SKIP`; a timeout or unexplained failure is not evidence of lack of
  support.
- Record per-peer evidence by scenario and transport in the runner PR. Do not
  count SKIP or unrelated draft versions as passes.

### Existing cases: preserve and triage (01–26)

| Range | Cases | Work |
| --- | --- | --- |
| 01–07 | setup-only; announce-only; publish-namespace-done; subscribe-error; rendezvous-timeout; announce-subscribe; subscribe-before-announce | Re-run control and namespace request lifecycles; compare the same case in both transports. |
| 08–11 | data-subgroup-basic; subscribe-namespace-lifecycle; publish-track-only; publish-track-subscribe | Verify complete delivery, PUBLISH completion, discovery removal, and session reuse. |
| 12–19 | moq-test-subgroup-per-group-eog; moq-test-subgroup-per-object; moq-test-two-subgroups-eog; moq-test-datagram; moq-test-datagram-eog; moq-test-extensions; moq-test-increments; moq-test-forward-zero | Re-run the complete Object validator and separate relay limitations from client encoding or receive defects. |
| 20–23 | publish-namespace-multi-publisher-retention; fetch; join; namespace-discovery | Diagnose source retention, historical delivery, Fill/live concurrency, and namespace/Track discovery independently. |
| 24–26 | publish-subscribe-media; media-catalog-error; media-loc-error | Preserve the bounded media case and rejection/recovery behavior; require real decoder output. |

### New cases: expand from 26 to 40

Each new scenario uses the existing draft-22 endpoint and fixture paths where
possible. Add no optional protocol framework solely to increase the count.

| Case | Scenario | Primary assertions |
| --- | --- | --- |
| 27 | moq-test-subgroup-per-group-no-eog | Complete Object set and Subgroup FIN without End-of-Group markers. |
| 28 | moq-test-subgroup-per-group-nonzero-start | Nonzero initial Group/Object IDs with one Subgroup per Group. |
| 29 | moq-test-subgroup-per-object-sparse-ids | Nonzero and incremented Object IDs across Subgroups. |
| 30 | moq-test-two-subgroups-no-eog | Odd/even Subgroup mapping and complete delivery without markers. |
| 31 | moq-test-datagram-nonzero-start | Datagram identity and completeness from nonzero initial IDs. |
| 32 | moq-test-datagram-sparse-ids | Datagram identity across sparse Group/Object IDs. |
| 33 | moq-test-extensions-integer-only | Integer Object Property encoding and byte-exact value. |
| 34 | moq-test-extensions-variable-only | Variable-length Object Property encoding and byte-exact value. |
| 35 | moq-test-object-fragmentation | Reassemble a multi-fragment Object and reject truncation. |
| 36 | moq-test-object-large-id | Round-trip large Group/Object IDs through draft-22 delta encoding. |
| 37 | publish-namespace-done-track | Complete a Track, withdraw its Namespace, then verify the independent observer sees the final removal. |
| 38 | subscribe-cancel-live | Cancel during live delivery and verify no post-cancel Objects reach the subscriber. |
| 39 | fetch-descending | FETCH a multi-Group range in descending order and verify every Object and completion boundary. |
| 40 | fetch-error-recovery | Reject an invalid FETCH range, then complete a valid FETCH on the same Session. |

After each case, run its targeted XQUIC self-pair case in QUIC and WebTransport,
then run the same case against aiomoqt and other registered draft-22 peers.
For a peer that explicitly does not support the operation, record the evidence
and skip that peer/case; keep the XQUIC self-pair requirement unchanged. After
case 40, run the full 40-case self-pair matrix and the 20-case, four-lane
aiomoqt matrix before preparing the runner update PR.

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
| 20 | Pinned independent interop | [Catalog][interop]; runner/images, complete-Object validator, media fixtures, independent peer evidence |

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
  complete-Object validator; separate evidence beyond the fixed 22-case catalog
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
