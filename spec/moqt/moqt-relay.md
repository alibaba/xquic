# MoQT Relay Specification

This specification defines the Relay core built on public endpoint APIs.
Endpoints and Relay are delivered separately. These requirements are not
evidence of a successful run or interoperability with independent peers.

Protocol basis: [draft-ietf-moq-transport-22 §7][s7], depending on the
[endpoint specification](moqt-protocol.md).

## Minimum Supported Scope

The first version is a single-process, single-node relay over Native QUIC or
optional WebTransport between original publishers and final subscribers.
It terminates independent
transport Sessions on both sides and routes/forwards Objects through public
protocol APIs. It depends on no private proxy format and performs no
cross-draft wire translation.

Both sides explicitly configure draft-22 and negotiate `moqt-22`, obeying
endpoint version/ALPN consistency. Preserving legacy draft-05/0-RTT does not
provide cross-version bridging.

| Capability | Relay core requirement |
| --- | --- |
| PUBLISH_NAMESPACE and direct PUBLISH | Required; authorize Namespace and specific Track independently |
| SUBSCRIBE routing, upstream establishment, downstream fanout | Required; multiple publishers/subscribers, Session-local IDs |
| Namespace discovery / TRACK_STATUS | Required; authorized registrations and upstream state |
| SUBSCRIBE_TRACKS / independent PUBLISH / PUBLISH_SKIPPED | Required for C10; reuse endpoint enumeration to create independent Pc from current sources and downstream authorization |
| Multiple publishers per Track, pause/resume, withdrawal | Required; §7.2–7.6 obligations |
| FETCH and subscription Fill | Required; retrieve from matching publishers without a history cache |
| Object/property/order/Delivery Mode fidelity | Required; permitted reencoding preserves Object semantics |
| Authorization, limits, slow-subscriber/error isolation | Required |
| Upstream subscription aggregation | Bounded compatible aggregation permitted; otherwise independent upstream requests |
| History cache, persistence, cache-only FETCH | Deferred; only bounded temporary queues needed for transport |
| Nonzero Range Filters, dynamic Groups | Deferred; retain endpoint rejection/negotiation boundaries |
| Relay cascading, routing protocol, loop discovery, cross-node state | Out of first-version scope; §7 defines no relay-to-relay interconnection mechanism |
| Automatic failover/GOAWAY migration, operational control plane | Deferred; expose standard messages/state and application policy |

The first version is an intermediate target. Claiming complete draft-22 Relay
support still requires all messages and §7 rules; endpoint optional subsets
do not waive Relay obligations.

The pinned interop catalog's `namespace-discovery` case requires
SUBSCRIBE_TRACKS. Endpoints already provide St enumeration, independent Pc,
and SKIPPED; Relay reuses them for cross-Session discovery without another
endpoint message implementation. Runner, container, and external-peer adapters
are outside this library. Local three-node success does not establish that
the independent interop case passes.

## Implementation Boundaries and Entity Design

Relay is an optional MoQ module above the endpoints. Its public entry point is
`include/moq/xqc_moqt_relay.h`; implementation lives in `moq/moqt_relay/`.
It uses only `xqc_moqt_*` endpoint APIs, shared codec/name helpers, and XQUIC
memory/containers. QUIC/TLS, draft-05 APIs, and connection negotiation acquire
no Relay-specific branch.

Endpoint additions are read-only queries for existing Location/known
termination decisions and current Largest, plus incoming Subgroup
END_OF_GROUP and the arrival time of an Object's first header byte. Relay
does not inspect private endpoint structures. END_OF_GROUP is retained from
the stream header and takes effect only on complete FIN. Continuation
fragments omit repeated properties; unknown and Immutable Properties preserve
their raw bytes. New subscriptions to direct PUBLISH use current Largest,
not a stale cached initial location.

| Protocol responsibility | Entity | References and lifetime |
| --- | --- | --- |
| Relay node | `xqc_moqt_relay_t` | Owns Peers, routing state, and total metadata budget; single-threaded |
| Independent hop/Session | `xqc_moqt_relay_peer_t` | Owns one endpoint Session and an explicit application Scope; destroy on connection close |
| Publication registration, discovery, queries, subscription control | `xqc_moqt_relay_request_t` | Weak endpoint Request handle, message snapshots, and upstream/downstream mappings; Request closure clears only that handle |
| Shared content identity | `xqc_moqt_relay_track_t` | Scope plus binary Full Track Name; associates sources/demand, never a global Alias key |
| Live delivery | Endpoint `xqc_moqt_subscription_t` | Relay Request retains an independent delivery reference until subscription termination, not Request FIN |
| Historical delivery | `xqc_moqt_relay_fetch_t` | Associates both Fetches and triggering requests; one absolute deadline, independent of Request FIN on either hop |
| Per-stream forwarding | `xqc_moqt_relay_stream_t` | One incoming-to-downstream stream mapping; endpoint APIs own FIN/reset, cancellation, and acknowledgment completion |

Each endpoint Session allocates its own Request IDs and Track Aliases. Relay
associates handles and never copies hop-local IDs/Aliases into responses.
Discovery registrations are counted by source Request. Notify DONE only when
the final source for that Namespace disappears. Direct PUBLISH associates a
specific Track without registering its Namespace.

This version advertises one update credit per Request and returns downstream
OK after the corresponding upstream update completes. Reuse the endpoint
FIFO rather than maintaining another concurrent update queue.

This version does not aggregate Object subscriptions. Each downstream demand
creates an independent SUBSCRIBE to each matching publisher, retaining that
demand's filters and delivery parameters. Direct PUBLISH may fan out to
multiple authorized downstreams. Each downstream pauses/resumes independently;
pause direct PUBLISH only when all matching demands are paused. This avoids
premature filter-union/shared-update scheduling. Incoming Tokens are removed;
application hop policy supplies outbound credentials.

Applications explicitly provide SETUP policy, request authorization, and
Scope. Peer creation/destruction follows connection creation/closure; start
its Session after handshake. Relay creates neither threads nor an event loop.
With `XQC_ENABLE_WEBTRANSPORT`, create a peer through
`xqc_moqt_relay_peer_create_webtransport` in WT session readiness after the
application authorizes CONNECT and selects `moqt-22`. It shares the native
peer's admission, policy, scope, and forwarding logic. The endpoint WT binding
requires draft-16 and forbids AUTHORITY/PATH SETUP Options (draft-22 §6.2.1,
§9.1.1/§9.1.2). Start its Session there and destroy the peer in WT session
close before H3 destruction. Peers on sibling WT Sessions remain independent.
Call its processing entry point after QUIC events and at the returned next
deadline. Closure callbacks immediately clear invalid handles; defer mapping
reclamation during callback traversal to prevent cross-Session dangling
references.

Relay Peer/Request/Stream/byte limits and each Session's stream/byte limits
both apply. Forward borrowed incoming fragments through endpoint send queues,
which copy them; do not add unlimited per-downstream payload queues. A queue
that cannot accept a fragment terminates only that downstream delivery while
healthy downstreams continue. Relay metadata, duplicate windows, and pending
operations consume its byte budget; payload consumes the destination Session
queue budget. The combined bound is the Relay budget plus all admitted
Sessions' configured bounds, with bounded Peer count. These are distinct
counters, not one interchangeable budget.

The first sufficient FETCH response fixes End Location before associating
the two Fetches. Fill uses its triggering response snapshot and each hop's
Request ID, without becoming a live Subgroup. Total budget starts with the
first request; queuing, response waits, and source changes cannot extend its
deadline. Downstream cancellation cancels its upstream request/Fetch and
streams, preserving other downstreams' independent requests.

Each historical operation initially chooses one authorized publisher, without
automatic source switching. Missing Fill ranges become independent FETCHes
to that publisher. Withhold FETCH_OK until End Location is sufficiently known.
An upstream unable to cover the promised Fill boundary causes
UNKNOWN_OBJECT_STATUS reset, never a shortened snapshot or invented
nonexistent Object. With no remaining budget and no Object yet, send a
timed-out range. If a partial Object cannot complete, reset DELIVERY_TIMEOUT
rather than sending an apparently complete FIN.

Duplicate detection retains a bounded identity/SHA-256 window, not historical
payload. Each new downstream has its own delivered window; prior delivery to
another subscriber must not suppress its Objects. If a duplicate Subgroup
record is skipped, reset any open output stream and use another for subsequent
records. Never continue across an omitted record and then FIN the old stream.
Objects outside the window are not claimed to be deduplicated. Conflicts
terminate only the affected Track, preserving unrelated Tracks/Sessions.
Payload digests are judged on complete reception; a delivered prefix cannot
be retracted, so conflict detection must terminate the affected delivery.

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

After NAMESPACE, C10 uses St to request Tracks. Once Relay accepts St, it
supplies matching, authorized, established publication sources to
`xqc_moqt_request_publish`. A source-instance ID is stable for the lifetime of
one publication; a new publication after reconnection uses a new ID. Reusable
pointer addresses must not serve as instance IDs. Repeated enumeration when
sources appear lets the endpoint suppress previously offered/skipped entries.
Relay enumerates authorized publishers whose Namespaces intersect. Each
publisher peer shares one upstream St with an empty prefix, authorized on
that hop; do not create overlapping upstream St for multiple downstreams.
This shares only name discovery, never Object authorization or filters.
Cancel upstream enumeration when the last relevant St disappears. New
upstream PUBLISH creates an independent source, re-enumerated for current
matching interest. Map each downstream Pc independently to its source and
Object delivery; Pc must not have St's lifetime. St cancellation releases
only upstream enumeration interest. Source PUBLISH and established downstream
Pc are reclaimed at their own delivery termination.
Never copy upstream credentials into downstream
PUBLISH. Relay owns downstream-origin exclusion, cross-Scope isolation, and
specific Track authorization; endpoint APIs provide neither cross-Session
routing nor authorization policy.

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
specific Track's PUBLISH. Namespace discovery, specific-Track control, and
Object delivery have separate lifetimes. SUBSCRIBE_TRACKS owns enumeration
interest only; generated PUBLISH independently retains its delivery mapping
through St cancellation or FIN. Live state notifications, FORWARD aggregation,
and source termination apply only to subscriptions. An independent FETCH for
the same Track neither counts as a live source nor terminates with live
notifications or cancellation.

| State | Ownership and commit conditions | Termination and isolation |
| --- | --- | --- |
| Pending rendezvous | Downstream interest and original deadline; match late PUBLISH to same-Track waiting requests | Commit success/failure/timeout once; late publication cannot revive cancelled state |
| Namespace source set | Authorized matching sources by Scope | DONE only after final source withdrawal; disappearance does not automatically terminate independent Track delivery |
| Independent demand | Each downstream retains filter/priority/deadline and creates an independent upstream request per source | Cancelling/pausing B1 preserves B2 dependencies; direct PUBLISH fans out under each downstream's policy |
| FETCH/Fill attempt | Original total timeout budget and definite End Location | No restart on source switch; cache miss/eviction/filter exclusion stays unknown; unfiltered FETCH explicitly marks gaps or resets UNKNOWN_OBJECT_STATUS |
| Asynchronous operation | Bound to owning Session/subscription/cancellation state | Late completion only releases; no dangling references, duplicate terminal state, or unlimited wait |

Match late publication to pending SUBSCRIBE, committing success only after
upstream Established. Add new publication sources to existing demand, rather
than retaining only the first publisher.

When the same subscriber also has a matching St, late PUBLISH SHALL satisfy
the pending SUBSCRIBE without another Pc. Check each St's merge condition
before committing SUBSCRIBE_OK so traversal order cannot erase the pending
state. Use PUBLISH_SKIPPED to record the publication instance for an uncreated
Pc. Neither later scans nor SUB cancellation may retry that instance; a new
publication instance may be enumerated. Cancelled/timed-out SUB requests do
not participate; other St-only subscribers receive Pc normally. [§7.6][s7.6]

Subscriber migration establishes new before cancelling old; B1 migration does
not migrate B2. Publisher rebuilds registration/PUBLISH on the new Session and
continues old-session sends until interest migrates. Deduplicate by Object
identity during overlap. Reallocate Aliases; application decides URI/credentials
without automatic inheritance. [§7.4.1][s7.4.1], [§7.6.1][s7.6.1]

Dynamic Groups, cache indexes, eviction, and replacement transactions remain
separate extensions. Temporary send queues are not history caches.

## Acceptance for the Separate Relay Implementation

These normal/abnormal scenarios SHALL have units and real
publisher → relay → subscriber tests, including at least two publishers and
two subscribers. Record Object bytes/metadata, request outcomes, endpoint
errors, and reclamation, not just process exit.

| Scenario | Normal acceptance | Abnormal / boundary acceptance |
| --- | --- | --- |
| ID/Scope isolation | Equal numeric IDs across downstreams associate correctly; independent cancellation | Same names in different Scopes do not share; .session never forwarded |
| Registration/discovery | OK/NAMESPACE, DONE only after last source; independent subscriptions continue | Single-Track rights cannot register Namespace; denied state pollutes neither routing nor discovery |
| Prefix Track subscriptions | B knows only the Namespace, discovers Tracks via Sns→St→Pc, and receives Objects; newly added Tracks are discovered | Existing Pc survives St cancellation; no echo to its publisher; no retry of a skipped publication, but a new publication after reconnection can be enumerated; no new Pc without interest and authorization |
| Sources/fanout | Complementary two-publisher Objects, two subscriber filters, mixed/all pause then resume | No OK before Established; timeout/cancel prevents late revival; reject excess sources |
| Objects/properties | Binary payload, Subgroup/Datagram, unknown properties, duplicate fidelity | Conflicts malformed; FIN cannot conceal gaps; no forwarding starts after TTL |
| FETCH/Fill | Upstream history without cache, concurrent live, correct End Location/mode/order | Total-budget timeout/unknown/reset; cancellation stops only unreferenced operations |
| Failure/resources | Healthy delivery continues, bounded queues/timers/routes reclaimed | Isolated slow-peer termination, malformed-upstream containment, all-upstream loss terminates affected delivery, no async UAF |
| Overlapping migration | New subscription succeeds before old cancellation; independent delivery and deduplication during overlap | B1 does not migrate B2; new Sessions inherit neither Aliases nor credentials |

Regression entry point: `case_test/moq/relay.sh`. Case 1475 covers routing,
discovery, filters/pause, Datagrams, and overlapping migration; 1476 covers
slow-subscriber, authorization, and malformed-Track isolation. Cases 1477/1478
cover FETCH/Fill success and live delivery after history failure; 1479/1480
cover St→Pc discovery, independent lifetimes, authorization, and SKIPPED.
Units additionally cover Scope, zero budgets, timeouts, empty streams,
allocation limits, state notifications, and callback cleanup. External runner
results are separate; these three-node self-tests do not replace independent
interoperability evidence.

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
