# Tasks

- [x] Refresh the requested base and create the requested branch.
- [x] Audit API, callback, context and lifecycle gaps.
- [x] Check current IETF and Chrome/QUICHE compatibility.
- [x] Add the HTTP/3 extension integration boundary.
- [x] Implement the WT context/session foundation and required data APIs.
- [x] Add demo server opt-in and a local browser test page.
- [x] Add happy-path and abnormal-path unit coverage.
- [x] Build and run the complete unit suite.
- [x] Run a loopback native integration test.
- [x] Remove engine and H3 request changes; verify connection-owned context
  teardown and existing H3 request/handshake callback routing.
- [ ] Verify real Chrome connection, data exchange, rejection and close.
- [x] Synchronize durable documentation and record remaining API gaps.
- [x] Prepare the scoped change and honest validation evidence for a draft PR.

Chrome control currently lacks its native messaging component. Server work
continues while the user enables the browser connection. Browser results
cannot be claimed until a real Chrome run succeeds.
