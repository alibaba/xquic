# Relay Design Entry Points

Protocol basis: draft-22 §§3.2.3, 3.4, 4, 7, and 9.20.5–9.20.6.
The [Relay specification](../../../spec/moqt/moqt-relay.md) defines normative
behavior, entity associations, and ownership.

Implement a separate optional MoQ Relay module. Public headers depend on
neither tests nor private endpoint structures. Reuse endpoint Session,
Request, Subscription, Fetch, and Stream; add no protocol parser, Alias
allocator, or second stream scheduler. Necessary endpoint queries expose
existing decisions rather than duplicating filtering algorithms.

Use independent upstream subscriptions instead of filter aggregation to
reduce shared cancellation/update state. Requests consequently grow with the
publisher/subscriber combinations, requiring explicit limits and rejection
tests. Registration and actual delivery have separate lifetimes. Clear
invalidated handles immediately in callbacks and defer mapping reclamation.

Extend existing MoQ feature routing for builds and cases. Measure production
coverage against the endpoint baseline, including Relay and necessary endpoint
extensions; existing base-branch code must not dilute the increment.

St reuses the Relay Request entity. Each publisher peer in a Scope has one
upstream St with an empty prefix, avoiding PREFIX_OVERLAP for downstreams with
the same prefix. Authorize that enumeration on its outbound hop and do not
inherit one downstream's delivery restrictions. Cancel the upstream St after
the last relevant downstream St disappears; Object authorization and Pc
filters remain independent.

Returned PUBLISH requests are independent sources. Relay allocates monotonic,
non-reusable source-instance IDs, applies outbound authorization per source,
and invokes endpoint enumeration to create downstream Pc. Pc references its
source, never St. Cancelling St ends enumeration and its upstream St while
established Pc continues delivery. Re-enumerate on source arrival and St
creation/update; endpoints suppress offered/skipped instances. Reconnection
creates a new ID; pointer addresses are not identities.

For late publication, enumerate St before committing pending SUBSCRIBE.
For a pending SUB on the same peer and scoped Track, reuse endpoint SKIPPED
records to suppress an extra Pc, without another routing entity or temporary
flag. Cancelled/timed-out requests do not participate; other peers remain
independent.
