# Tasks

- [x] Refresh the requested base and create the requested branch.
- [x] Audit API, callback, context and lifecycle gaps.
- [x] Check current IETF and Chrome/QUICHE compatibility.
- [x] Integrate WT through existing ALPN callbacks and minimal H3 SETTINGS access.
- [x] Implement the WT context/session foundation and required data APIs.
- [x] Add demo server opt-in and a local browser test page.
- [x] Add happy-path and abnormal-path unit coverage.
- [x] Build and run the complete unit suite.
- [x] Run a loopback native integration test.
- [x] Remove engine and H3 request changes; verify connection-owned context
  teardown and existing H3 request/handshake callback routing.
- [x] Move stream classification, buffering and lifecycle state into the WT
  adapter; cover prefix fragmentation, ordinary H3 fallback and FIN retries.
- [x] Remove the generic H3 extension framework; restore H3 context and stream
  lifecycle paths, and verify existing ALPN callback ownership and GOAWAY.
- [ ] Verify real Chrome connection, data exchange, rejection and close.
- [x] Expose one H3 setting registration API, remove the extended writer,
  and verify registration, duplicate updates and frozen/invalid input rejection.
- [x] Synchronize durable documentation and record remaining API gaps.
- [x] Prepare the scoped change and honest validation evidence for a draft PR.

Chrome control currently lacks its native messaging component. Server work
continues while the user enables the browser connection. Browser results
cannot be claimed until a real Chrome run succeeds.
