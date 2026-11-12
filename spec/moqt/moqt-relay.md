# MoQT Relay Specification

This shared specification defines the target for a separate Relay
implementation. The endpoint change does not implement Relay; this document
is not evidence of validated Relay behavior.

Protocol basis: [draft-ietf-moq-transport-22 §7][s7], depending on the
[endpoint specification](moqt-protocol.md).

## Minimum Supported Scope

The first version is a single-process, single-node Native QUIC relay between
original publishers and final subscribers. It terminates independent
transport Sessions on both sides and routes/forwards Objects through public
protocol APIs. It depends on no private proxy format and performs no
cross-draft wire translation.

Both sides explicitly configure draft-22 and negotiate `moqt-22`, obeying
endpoint version/ALPN consistency. Preserving legacy draft-05/0-RTT does not
provide cross-version bridging.

| Capability | Separate Relay implementation requirement |
| --- | --- |
| PUBLISH_NAMESPACE and direct PUBLISH | Required; authorize Namespace and specific Track independently |
| SUBSCRIBE routing, upstream establishment, downstream fanout | Required; multiple publishers/subscribers, Session-local IDs |
| Namespace discovery / TRACK_STATUS | Required; authorized registrations and upstream state |
| Multiple publishers per Track, pause/resume, withdrawal | Required; §7.2–7.6 obligations |
| FETCH and subscription Fill | Required; retrieve from matching publishers without a history cache |
| Object/property/order/Delivery Mode fidelity | Required; permitted reencoding preserves Object semantics |
| Authorization, limits, slow-subscriber/error isolation | Required |
| Upstream subscription aggregation | Bounded compatible aggregation permitted; otherwise independent upstream requests |
| History cache, persistence, cache-only FETCH | Deferred; only bounded temporary queues needed for transport |
| SUBSCRIBE_TRACKS, Range Filters, dynamic Groups | Deferred; retain endpoint rejection/negotiation boundaries |
| Relay cascading, routing protocol, loop discovery, cross-node state | Out of first-version scope; §7 defines no relay-to-relay interconnection mechanism |
| Automatic failover/GOAWAY migration, operational control plane | Deferred; expose standard messages/state and application policy |

The first version is an intermediate target. Claiming complete draft-22 Relay
support still requires all messages and §7 rules; endpoint optional subsets
do not waive Relay obligations.

## Relay Requirements

### Requirement: Endpoint Reuse and Cross-Session ID Isolation

Relay SHALL reuse the endpoint library with independent upstream/downstream
Session, Request, Track Alias, and Stream mappings. Full Track Name keys
include application-defined Scope, preventing accidental sharing across
authorities/paths. Allocate valid per-hop Request IDs/Aliases rather than
copying Session-local IDs.

Relay SHALL handle `.session` locally, never forward it. Ordinary Object payloads are
not decoded, concatenated, split, or repackaged.
[§6.5][s6.5], [§7.8][s7.8]

### Requirement: Registration, Discovery, and Authorization

Relay SHALL authorize PUBLISH_NAMESPACE Namespace rights separately from PUBLISH Track
rights. Permission for one Track does not authorize its whole Namespace.
Direct PUBLISH does not implicitly create Namespace routing. Applications
must supply explicit authentication/authorization policy.

Relay SHALL retain authorized registrations by tuple prefix. After SUBSCRIBE_NAMESPACE
OK, send NAMESPACE/DONE rather than forwarding PUBLISH_NAMESPACE.
Withdrawal, expired authorization, and disconnect update registration.
Existing subscription termination depends on its own valid upstream state.
[§4][s4], [§7.6][s7.6]

Authorize discovery and subscription separately. TRACK_STATUS must not disclose
unauthorized Track existence/properties. Unknown sources/denied Namespaces
never enter the discoverable set.

### Requirement: Routing, Fanout, Multiple Publishers, and Pause

On SUBSCRIBE, Relay SHALL match Full Track Name/Namespace prefix and establish/maintain
required upstream subscriptions to all matching publishers under §7.6.
Send downstream SUBSCRIBE_OK only after at least one corresponding upstream
subscription is Established, not merely sent. [§7.3–7.6][s7.3]

Relay SHALL support multiple publishers of one Track without silently retaining only the
first accepted publisher. Bound publisher count if needed, explicitly
rejecting/cancelling excess. First-version tests include two accepted
publishers. New registrations matching existing interest establish additional
upstream subscriptions.

Relay SHALL forward each Object to every matching unpaused downstream subscription,
retaining independent filters/priorities/timeouts. If one Object matches
multiple same-Track subscriptions, deliver separately rather than deduplicating
away a subscription.

While any downstream is unpaused, Relay SHALL keep required upstreams unpaused and resume
relevant paused ones under §7.6. With all downstreams paused, this version
pauses upstreams to save resources; resume must not lose REQUEST_UPDATE.
Without cache, aggregate only compatible upstream interest. Incompatible
filter/authorization semantics require independent requests, without widening
permissions.

RENDEZVOUS_TIMEOUT zero/omitted with no publisher SHALL return DOES_NOT_EXIST.
Nonzero uses bounded waiting and TIMEOUT at expiry, proceeding only if a
publisher appears. Do not send SUBSCRIBE_OK while waiting.
[§9.20.6][s9.20.6]

### Requirement: Object and Property Fidelity

Relay SHALL preserve payload, Group/Object/Subgroup IDs, priority, and Delivery Mode.
Propagate Track/Object Properties under §8.4 and each definition.
Retain unknown ordinary properties. Updates to one Object use its newest
complete unknown-property set, not a union. Never reencode/change/add/remove
raw Immutable Properties bytes, including non-minimum integers.
Propagate unsupported Mandatory Track Properties under §3.7.
[§7.7–7.8][s7.7]

Even without history cache, Relay SHALL obey MAX_CACHE_DURATION from each Object's
reception start. Do not begin forwarding after expiry; temporary queues cannot
bypass it. Expired status is unknown. Applicable delivery timeouts also apply.

Relay SHALL preserve multi-Object Subgroup ordering/reliability. Do not discard one Object
then FIN as if complete. If the next Object's continuity cannot be established,
reset the old stream and open another under §11.3.2, without hiding a gap
inside an apparently complete stream.

Bounded duplicate suppression is permitted. Conflicting payload, Delivery Mode,
Subgroup ID, or priority among retained/observed duplicates SHALL be treated as malformed Track.
Unknown, nonexistent, and late Objects follow §2.1.2; a late Object after
ordinary nonexistence is not itself malicious conflict.
[§7.1][s7.1], [§12.1][s12.1]

### Requirement: FETCH and Fill Without a History Cache

Relay SHALL route downstream FETCH to at least one authorized matching publisher with an
independent Request ID. No local cache does not mean every historical Object
is nonexistent. Wait for enough information to determine End Location before
FETCH_OK. [§3.2.3][s3.2.3], [§7.6][s7.6]

Relay SHALL obtain missing subscription Fill through upstream Fill or FETCH. Downstream
Fill uses the triggering Request ID. Without cache, retrieve all required
history upstream; an arbitrary upstream FETCH stream cannot become a
downstream live Subgroup.

FILL_TIMEOUT SHALL be the total budget across all upstream attempts, never reset
on retry/source switch. Zero does not wait upstream; unavailable immediate
Objects become timed-out ranges. Use unknown ranges/applicable reset for
upstream failure/unknown Objects, timed-out ranges for budget exhaustion.
Never conceal errors with nonexistent ranges. [§9.20.5][s9.20.5]

### Requirement: Resource, Failure, and Slow-Subscriber Isolation

Relay SHALL set/test finite request/stream/queue/byte/time limits per Session, publisher,
subscriber, and Track. Forward through incremental Object APIs; waiting for
complete large Objects cannot grow queues without bound.
[§7.5][s7.5], [§15.7][s15.7]

Relay SHALL terminate/reset an over-limit slow subscription with TOO_FAR_BEHIND or the
applicable error while preserving Subgroup semantics. Its backpressure must
not block healthy subscribers. Malformed input closing one Session must not
propagate elsewhere. When all upstreams disappear, terminate affected
subscriptions rather than retaining false Established state indefinitely.

Closure SHALL clean routes, mappings, timers, TX queues, and asynchronous
tasks. Provide reason-specific rejection/discard/timeout/queue counters.
Never log Tokens.

<a id="relay-integration"></a>

## Cross-Session State and Lifetimes

Sns is Namespace discovery, St is a prefix Track subscription, and Pc is a
specific Track's PUBLISH. None owns the others' delivery lifetime.

| State | Ownership and commit conditions | Termination and isolation |
| --- | --- | --- |
| Pending rendezvous | Downstream interest and original deadline; match late PUBLISH to same-Track waiting requests | Commit success/failure/timeout once; late publish cannot revive cancelled state or duplicate PUBLISH to B |
| Namespace source set | Authorized matching sources by Scope | DONE only after final source withdrawal; disappearance does not automatically terminate independent Pc |
| Aggregated demand | Independent downstream filter/priority/deadline; upstream covers authorized Object union | Cancelling/pausing B1 preserves B2 dependencies; excess ranges may widen filtering within authorization/budget or add upstreams, followed by per-downstream filtering |
| FETCH/Fill attempt | Original total timeout budget and definite End Location | No restart on source switch; cache miss/eviction/filter exclusion stays unknown; unfiltered FETCH explicitly marks gaps or resets UNKNOWN_OBJECT_STATUS |
| Asynchronous operation | Bound to owning Session/subscription/cancellation state | Late completion only releases; no dangling references, duplicate terminal state, or unlimited wait |

Prefer matching late publication to pending SUBSCRIBE. Only matched
SUBSCRIBE_TRACKS without pending SUBSCRIBE creates an independent PUBLISH by
discovery rules. Success waits for upstream Established. Add new publication
sources to existing demand, rather than retaining only the first publisher.

Subscriber migration establishes new before cancelling old; B1 migration does
not migrate B2. Publisher rebuilds registration/PUBLISH on the new Session and
continues old-session sends until interest migrates. Deduplicate by Object
identity during overlap. Reallocate Aliases; application decides URI/credentials
without automatic inheritance. [§7.4.1][s7.4.1], [§7.6.1][s7.6.1]

Dynamic-Group outstanding aggregation is separate from subscription update
credit; see [completion rules](moqt-protocol.md#dynamic-group-design).
Cache indexes, eviction, and replacement transactions remain a separate
extension. Temporary send queues are not history caches.

## Acceptance for the Separate Relay Implementation

These normal/abnormal scenarios SHALL have units and real
publisher → relay → subscriber tests, including at least two publishers and
two subscribers. Record Object bytes/metadata, request outcomes, endpoint
errors, and reclamation, not just process exit.

| Scenario | Normal acceptance | Abnormal / boundary acceptance |
| --- | --- | --- |
| ID/Scope isolation | Equal numeric IDs across downstreams associate correctly; independent cancellation | Same names in different Scopes do not share; .session never forwarded |
| Registration/discovery | OK/NAMESPACE, DONE only after last source; independent subscriptions continue | Single-Track rights cannot register Namespace; denied state pollutes neither routing nor discovery |
| Sources/fanout | Complementary two-publisher Objects, two subscriber filters, mixed/all pause then resume | No OK before Established; timeout/cancel prevents late revival; reject excess sources |
| Objects/properties | Binary payload, Subgroup/Datagram, unknown properties, duplicate fidelity | Conflicts malformed; FIN cannot conceal gaps; no forwarding starts after TTL |
| FETCH/Fill | Upstream history without cache, concurrent live, correct End Location/mode/order | Total-budget timeout/unknown/reset; cancellation stops only unreferenced operations |
| Failure/resources | Healthy delivery continues, bounded queues/timers/routes reclaimed | Isolated slow-peer termination, malformed-upstream containment, all-upstream loss terminates affected delivery, no async UAF |
| Aggregation/migration | Authorized union, new subscription established before old cancellation | Per-downstream filtering despite range overflow; B1 does not migrate B2; no old Alias/credential inheritance |

These scenarios are not implemented yet. Allocate case IDs when implementing
Relay under repository rules.

Prove routing, rights, multi-publisher behavior, fanout, FETCH/Fill, unknown
properties, slow consumers, timeouts, and disconnects separately. Endpoint
self-tests do not validate Relay. Cross-check independent draft-22
publishers/subscribers where possible; record unsupported-peer gaps.

A future cache extension separately defines keys, MAX_CACHE_DURATION, field
integrity, eviction, unknown state, duplicate updates, and poisoning defenses.
Do not market first-version send queues as caches.

[s4]: https://datatracker.ietf.org/doc/html/draft-ietf-moq-transport-22#section-4
[s6.5]: https://datatracker.ietf.org/doc/html/draft-ietf-moq-transport-22#section-6.5
[s7]: https://datatracker.ietf.org/doc/html/draft-ietf-moq-transport-22#section-7
[s7.1]: https://datatracker.ietf.org/doc/html/draft-ietf-moq-transport-22#section-7.1
[s7.3]: https://datatracker.ietf.org/doc/html/draft-ietf-moq-transport-22#section-7.3
[s7.5]: https://datatracker.ietf.org/doc/html/draft-ietf-moq-transport-22#section-7.5
[s7.6]: https://datatracker.ietf.org/doc/html/draft-ietf-moq-transport-22#section-7.6
[s7.7]: https://datatracker.ietf.org/doc/html/draft-ietf-moq-transport-22#section-7.7
[s7.8]: https://datatracker.ietf.org/doc/html/draft-ietf-moq-transport-22#section-7.8
[s3.2.3]: https://datatracker.ietf.org/doc/html/draft-ietf-moq-transport-22#section-3.2.3
[s9.20.5]: https://datatracker.ietf.org/doc/html/draft-ietf-moq-transport-22#section-9.20.5
[s9.20.6]: https://datatracker.ietf.org/doc/html/draft-ietf-moq-transport-22#section-9.20.6
[s12.1]: https://datatracker.ietf.org/doc/html/draft-ietf-moq-transport-22#section-12.1
[s15.7]: https://datatracker.ietf.org/doc/html/draft-ietf-moq-transport-22#section-15.7
[s7.4.1]: https://datatracker.ietf.org/doc/html/draft-ietf-moq-transport-22#section-7.4.1
[s7.6.1]: https://datatracker.ietf.org/doc/html/draft-ietf-moq-transport-22#section-7.6.1
