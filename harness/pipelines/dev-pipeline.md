# Development Pipeline

This is the issue-independent workflow for XQUIC code changes. It adapts the
development loop from the reference harness to the specifications and
validation entry points maintained in this repository.

Reading this file in full is a mandatory preflight for every code task. Read
it before planning, inspecting implementation paths, or editing source,
tests, build scripts, validation tooling, or repository automation.

```text
Requirement analysis -> Acceptance criteria -> Working branch
                     -> Implementation -> Validation
                     -> Draft PR -> Pre-review -> Ready for review
```

## Stage 1: Requirement Analysis

1. Read `AGENTS.md` and the
   [project instructions](../spec/PROJECT_INSTRUCTIONS.md).
2. Classify whether the task fixes a reported issue. If it does:
   1. Run the [`issue-check` skill](../skills/issue-check/SKILL.md) against
      the issue, the authoritative RFC or draft, and the current checkout.
   2. Verify the issue's truth gate and investigate the source root cause,
      preserving the complete required report, source excerpts, commit SHA,
      root-cause status, and blocking evidence.
   3. Write the report to the task-scoped, ignored temporary artifact
      `build/harness/<task-id>/issue-check.md`. Do not stage or commit it.
   4. Continue the issue fix only when `check_result: true`. For
      `not-a-problem`, stop the fix and report the verified explanation. For
      `inconclusive`, gather the blocking evidence and rerun `issue-check`
      before deciding whether implementation is justified.
3. Identify the affected modules using the
   [architecture map](../spec/architecture.md).
4. Read the relevant source, callers, tests, public headers, and module docs.
5. For wire behavior, identify the governing RFC or draft section.
6. Record non-goals and unrelated local changes that must remain untouched.

Exit when the current behavior, desired behavior, affected boundary, and
source of truth are understood. For an issue fix, the task-scoped issue-check
report must exist, its gate must be true, and its root-cause status and any
blocking evidence must be explicit.

## Stage 2: Acceptance Criteria

1. For an issue fix, use the issue-check report's verified specification,
   implementation comparison, and root-cause analysis as requirement inputs.
2. Express completion as observable behavior rather than an issue-specific
   build mode, branch name, or configuration flag.
3. Identify a happy-path unit test for the changed behavior.
4. Identify an abnormal, rejection, boundary, or error-branch unit test.
5. Identify matching happy-path and abnormal-path client-to-server cases in
   `scripts/case_test.sh`.
6. If either client-to-server case is new, select a distinct, never-used ID
   for each case from the owning layer or module namespace in the
   [validation specification](../spec/validation.md#client-to-server-case-id-namespace).
   Refresh the base, search repository history, then inspect the published head
   SHA of every open pull request targeting `main`; do not select an ID already
   reserved in another PR's case selectors.
7. Identify broader compatibility or interoperability evidence when the
   paired tests cannot establish the peer-visible result.
8. Choose the expected validation level from the
   [validation specification](../spec/validation.md).

Exit when the criteria can distinguish the intended behavior from the
pre-change behavior and every proposed case ID has a complete, conflict-free
allocation snapshot.

## Stage 3: Working Branch

1. Classify the accepted task and select the exact branch pattern from
   [`CONTRIBUTING.md`](../../CONTRIBUTING.md#working-branch):

   - New feature: `dev/${feature_name}`
   - Bug fix: `fix/${function_or_module_name}`
   - Performance optimization or other enhancement:
     `perf/${optimization_item}`
   - Documentation: `doc/${documentation_name}`

2. Treat the `${...}` values as descriptive placeholders. The contribution
   guide does not require underscores or define a stricter character set for
   the expanded suffix.
3. Create the working branch from its intended base, normally `main`, before
   editing implementation files:

   ```bash
   git checkout -b <branch-name> main
   ```

4. Verify the result with `git branch --show-current`. The prefix must match
   the accepted task type; the four prefixes are not interchangeable, and an
   unlisted prefix such as `feat/` does not satisfy the contribution guide.
5. If the current branch contains unrelated local changes, preserve them and
   isolate the task in a separate worktree or clean checkout instead of
   moving or mixing them into the new branch.

Exit when the current branch was created from the intended base, contains
only the scoped task, and its name matches the task-type mapping above.

## Stage 4: Implementation

1. For an issue fix, read
   `build/harness/<task-id>/issue-check.md` before editing production code.
   Treat its verified mechanism, source trace, root-cause status, and blocking
   evidence as implementation inputs. Rerun `issue-check` if a relevant
   issue claim, specification revision, or source path changed.
2. Add or update paired happy-path and abnormal-path unit tests.
3. Add or update paired happy-path and abnormal-path client-to-server case
   tests. Give every new case its allocated ID and update the validation
   namespace registry in the same change.
4. Make the smallest production change that satisfies the criteria.
5. Follow `CONTRIBUTING.md` and adjacent project conventions.
6. Re-read the modified path and trace affected callers and callees.
7. Update durable specifications or module documentation when contracts,
   boundaries, commands, or maintenance obligations changed.

Exit when the implementation, tests, and durable documentation agree.

## Stage 5: Validation

Follow the [`validate` skill](../skills/validate/SKILL.md). Before a production
code pull request, run the complete local unit suite with `XQC_TEST_NAME`
unset, then run both relevant client-to-server case tests:

```bash
unset XQC_TEST_NAME
./scripts/validate.sh test
```

Use `XQC_BUILD_DIR=build ./scripts/validate.sh full` when the paired case-test
blocks cannot be run independently. Record exact commands, paired test names,
and results in ignored local validation artifacts. Do not submit a new pull
request or move an existing pull request to review after a missing or failed
gate.

For every new case ID, repeat the open-PR reservation scan after the tests pass
and immediately before Stage 6. Record the candidate IDs, query time, number of
published PR heads inspected, current PR exclusion, and result. Fail closed if
the open-PR query, fetch, or head-SHA verification is incomplete.

Exit only when the complete unit suite and both relevant case tests pass and
the final reservation snapshot is complete and conflict-free.

## Stage 6: Draft PR, Pre-Review, and Review Submission

1. Review staged and unstaged diffs separately and verify the final scope.
2. Confirm generated headers, validation artifacts, and task-scoped
   `build/harness/` issue-check reports are absent from the commit.
3. Check that documentation links and referenced commands still resolve.
4. Assemble the evidence required by the
   [pull-request specification](../spec/pull-requests.md).
5. Complete the repository
   [pull-request template](../../.github/pull_request_template.md) as a concise
   review summary:
   - explain the changed mechanism and cite the exact RFC or draft section
     when protocol behavior changes;
   - list each client-to-server case as only `<ID> — <concise behavior>`;
   - report one aggregate `CONTRIBUTING.md` result; and
   - mark local regression and CI `Complete`, or name only incomplete checks
     and concise failing cases.
   Do not copy commands, test function names, logs, namespace ranges, tested
   SHA, or successful reservation snapshots into the PR body.
6. After Stage 5 passes, invoke the
   [`xquic-pr-formatting` skill](../skills/xquic-pr-formatting/SKILL.md) to
   format and submit every new code pull request as draft, or update an
   existing pull request after a follow-up revision and keep it in draft,
   through the available GitHub client.
7. Fetch the published pull request and verify its number, URL, base commit,
   head commit, title, body, and draft state. Run the
   [`xquic-pr-pre-review` skill](../skills/xquic-pr-pre-review/SKILL.md)
   against that exact published base-to-head diff. Write its five-part report
   to
   `~/build/harness/pr-review-<number>/pr-review-<number>.md`. Keep all
   reviewer-created abnormal-case code and supporting artifacts in the same
   local review directory so they can be reused in the next iteration.
8. Continue only when the report reviews the published current head and says
   `pre_review_result: true`. Keep the complete local review directory
   unstaged and uncommitted. A changed published head invalidates the report,
   returns the pull request to this step, and may reuse retained abnormal-case
   artifacts only after rerunning them against the new head.
9. Immediately scan open pull requests again with the published current PR
   included. If two PRs contain the same case ID, the lower-numbered PR keeps
   it. Keep or return every later PR to draft, then go back to Stage 2,
   reallocate the colliding ID, update the selectors and registry, and rerun
   Stage 5 before publishing another head.
10. Reflect a post-publication collision as an incomplete local-regression
   blocker; keep successful scan details in local evidence. Fetch the published
   pull request and verify its title, concise body, real line breaks, issue and
    RFC linkage, aggregate gates, base, head, draft or review state, and URL.
    Only then update the concise body and move an otherwise complete PR to
    review.

Complete the loop only when the acceptance criteria, paired unit and case-test
coverage, validation evidence, five-part pre-review, scope review, and
published pull request are consistent.

## Enforcement Rules

1. Build and validation interfaces must not depend on a feature, bug, issue
   number, or pull request.
2. A behavior-changing code edit must not leave stale tests or durable
   documentation.
3. Every production behavior change requires paired happy-path and
   abnormal-path unit tests.
4. Every production behavior change requires paired happy-path and
   abnormal-path client-to-server case tests.
5. Every new client-to-server case has a distinct, never-used ID from the
   documented namespace, active or retired IDs are never reused, and an ID
   reserved by another open pull request is unavailable.
6. A failed build is resolved before tests continue.
7. The complete local unit suite and relevant case-test pair must pass before
   review.
8. Generated and temporary artifacts are never committed as source.
9. A production code pull request reports incomplete local or CI gates
   truthfully and remains draft while required paired coverage or local
   validation is missing or failed.
10. An issue fix must not enter implementation with a false or inconclusive
    issue-check gate, and its task-scoped issue-check report must never be
    committed.
11. A new pull request is submitted only after the Stage 5 validation gate
    passes, and every submission or follow-up update uses
    `xquic-pr-formatting` and verifies the published result.
12. Case-ID allocation fails closed unless the base, repository history, and
    all open PR heads were checked. A post-publication collision is resolved in
    favor of the lowest PR number; a later PR must reallocate and revalidate.
13. Every new code pull request is submitted as draft after validation. It is
    moved to review only when its exact published current head has a true
    five-part pre-review result; the PR-scoped local retrospective and
    abnormal-case artifacts are never committed.
