# Implementation and Acceptance

- [x] Establish endpoint boundaries and protocol basis; reuse C10 enumeration.
- [x] Define Relay entities, ownership, and resource policy in the public spec.
- [x] Integrate St→independent Pc, stable source instances, and SKIPPED; cover
  authorization, self-origin exclusion, Pc surviving St cancellation, and
  enumeration of new Tracks and publication instances.
- [x] Implement hop-local routing, source sets, Established gating, rendezvous.
- [x] Verify both pending SUB/St arrival orders, cancellation/timeouts, and
  re-enumeration; no duplicate Pc for the same peer, while St-only peers
  continue delivery.
- [x] Implement independent subscriptions, incremental fanout, mixed pause,
  and slow-subscriber isolation.
- [x] Implement FETCH/Fill mappings, total budgets, cancellation, and late
  callback cleanup.
- [x] Cover malformed Tracks, duplicate Objects, disconnects, and overlapping
  old/new Sessions.
- [x] Add paired units and three-node cases with two publishers/subscribers.
- [x] Check new case IDs against the current tree, history, and all open PRs.
- [x] Run complete MoQ ON/OFF, endpoint regression, harness/format checks, and
  production-delta coverage.
- [ ] Push an independent PR; verify MoQ Matrix, both TLS unit/regression
  profiles, and at least 90% remote production-delta coverage; submit the
  primary diff for review. Record unavailable jobs as evidence gaps.

The Relay specification's acceptance table governs request outcomes, Object
fields, state reclamation, and resource limits. Keep logs and run snapshots in
ignored build artifacts, outside durable specifications.
