---
name: xquic-pr-pre-review
description: Perform a fail-closed pre-review of a published draft XQUIC code pull request before ready-for-review state. Verify its exact published base-to-head implementation against authoritative RFC or pinned Internet-Draft text, paired positive and negative unit and client-to-server case coverage, an attempted adversarial bypass, protocol-stack performance and compiler optimization, and memory safety, ownership, bounds, and footprint; write the five-part conclusion to an ignored local review file.
---

# XQUIC PR Pre-Review

Review the published pull request's exact base-to-head diff and write the
result to `build/harness/pr-<number>/pre-review.md`. Require a GitHub PR number
and URL; do not substitute a local branch candidate. Never stage or commit the
report or exploratory review artifacts.

## Inputs and Gate

1. Fetch the pull request from GitHub. Record its number, URL, base commit,
   published head commit, changed files, draft state, and review time.
2. Confirm the fetched head matches the PR's published head, then read the
   changed implementation, callers, tests, architecture map, and
   adjacent module documentation. Treat the PR and issue descriptions as
   context, not evidence.
3. For protocol behavior, retrieve the authoritative text from RFC Editor or
   the IETF Datatracker. Pin an Internet-Draft to the revision implemented by
   the repository. Record the document URL, exact section, normative keyword,
   and a source excerpt of no more than 25 words. Do not rely on a quotation
   copied into the PR or issue.
4. Use `pass`, `fail`, `inconclusive`, or `not-applicable` for each section.
   Use `not-applicable` only with a concrete scope reason.
5. Set `pre_review_result: true` only when every section is `pass` or justified
   `not-applicable`. A `fail` or `inconclusive` result is a closed gate.
6. Invalidate and rerun the report whenever the published PR head changes.

If the official specification, reviewed source, or current-head validation
evidence cannot be inspected, return `inconclusive`; never infer a pass.

## 1. RFC Conformance

- Derive the affected protocol mechanism from the code and wire behavior.
- Compare every changed state transition, limit, role restriction, error code,
  and peer-visible result with the authoritative section.
- Trace peer input from parsing through validation, state mutation, and error
  handling. Cite current file and line evidence.
- Check interactions with related RFC requirements and negotiated extensions,
  not only the paragraph cited by the PR.
- Check verified RFC errata or pinned-draft changes that alter the cited
  mechanism.
- Fail on a semantic deviation unless the RFC permits the implementation
  choice and the report explains that allowance.

## 2. Validation Coverage

- Inspect committed tests rather than trusting the PR summary.
- Require a positive and negative CUnit case tied to each changed production
  path.
- Require positive and abnormal client-to-server cases in
  `scripts/case_test.sh`, with distinct IDs and matching selectors in
  `tests/test_client.c` and `tests/test_server.c`.
- Confirm the end-to-end cases prove the endpoint-visible result, not merely a
  process exit or generic failure.
- Verify current-head local evidence shows the complete CUnit suite and both
  relevant case tests passed. Fail when coverage or current-head evidence is
  missing.

## 3. Adversarial Bad Case

- Construct the smallest peer-controlled input or event sequence that could
  bypass the RFC guard. Consider boundary values, duplicate or reordered
  frames, wrong endpoint roles, invalid state transitions, truncated or
  non-canonical encodings, retransmission, 0-RTT, and callback reentrancy when
  relevant.
- Trace the bad case through the actual parser and state machine. Attempt an
  executable focused unit or client-to-server reproduction when the local
  environment permits it.
- Keep exploratory code, packets, and logs under the task review directory;
  do not modify the submitted diff.
- Fail when the bad case bypasses the intended restriction or exposes an
  unhandled state. Return `inconclusive` when a material bad case cannot be
  executed or ruled out.

## 4. Performance and Compiler Optimization

- Identify whether the change is on a packet, frame, stream, request, timer, or
  connection hot path and estimate its invocation frequency.
- Compare the time complexity and critical-path work with viable alternatives.
  Check repeated scans, avoidable parsing, allocations, copies, branches,
  cache-unfriendly access, locking, and contention.
- Inspect whether types, aliasing, control flow, data layout, and function
  boundaries allow the configured compiler to inline, fold constants,
  eliminate dead work, and vectorize where useful.
- Read the actual release build flags before assuming an optimization is
  enabled.
- Use optimized-build assembly, compiler remarks, profiles, or benchmarks for
  material performance claims when practical. Do not call an implementation
  optimal without evidence.
- Fail on an avoidable asymptotic regression or a material hot-path slowdown
  without a correctness requirement or measured tradeoff.

## 5. Memory Safety and Footprint

- Build an ownership and lifetime map for every touched allocation, buffer,
  pointer, list node, callback context, and borrowed reference.
- Check success, error, timeout, close, retry, and reentrant callback paths for
  leaks, double frees, use-after-free, stale aliases, null dereferences,
  integer overflow, out-of-bounds access, and length/capacity mismatches.
- Quantify new long-lived bytes per connection, stream, request, and path.
  Project server cost at realistic concurrency and check for unbounded or
  peer-controlled retention.
- Use sanitizer, static-analysis, or focused stress evidence when the changed
  ownership or bounds cannot be proved by inspection.
- Prefer execution efficiency when memory footprint and speed conflict, but
  record the alternatives, concurrency cost, measured or reasoned speed
  benefit, and why the retained memory is bounded and acceptable.

## Report Format

Write exactly five numbered review sections after the metadata:

```markdown
---
reviewed_base: <commit>
reviewed_head: <commit>
review_target: <PR URL>
review_time_utc: <timestamp>
pre_review_result: <true|false>
---

# XQUIC PR Pre-Review

## 1. RFC Conformance
Status: <pass|fail|inconclusive|not-applicable>
Sources: <official document, section, URL>
Evidence: <source/tests and short authoritative excerpt>
Findings: <blocking and non-blocking findings, or none>
Conclusion: <reasoned conclusion>

## 2. Validation Coverage
Status: <...>
Evidence: <positive/negative unit and end-to-end case IDs/results>
Findings: <...>
Conclusion: <...>

## 3. Adversarial Bad Case
Status: <...>
Attempt: <constructed input or sequence and execution result>
Findings: <...>
Conclusion: <...>

## 4. Performance and Compiler Optimization
Status: <...>
Evidence: <hot path, complexity, compiler and measurement evidence>
Findings: <...>
Conclusion: <...>

## 5. Memory Safety and Footprint
Status: <...>
Evidence: <ownership, bounds, per-scope footprint and concurrency estimate>
Tradeoff: <memory versus execution-efficiency decision>
Findings: <...>
Conclusion: <...>
```

For every blocking finding, cite the reviewed file and line, explain the
failure mode, and state the minimum condition for the gate to pass. Do not fix
the PR while performing pre-review unless the user separately requests it.
