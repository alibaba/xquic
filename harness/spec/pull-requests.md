# Pull Request Evidence

See the [project instructions](PROJECT_INSTRUCTIONS.md) for related
architecture and validation contracts. When drafting or updating a pull
request, follow the
[`xquic-pr-formatting` skill](../skills/xquic-pr-formatting/SKILL.md).
Start from the repository
[pull-request template](../../.github/pull_request_template.md).

Keep the pull request body short enough to scan. It contains only the changed
mechanism, concise validation cases, and the aggregate contribution gate.
Detailed commands, logs, test function names, and reservation snapshots remain
in code, CI, or ignored local validation artifacts.

## CONTRIBUTING.md Compliance

The repository [contribution guide](../../CONTRIBUTING.md) remains the
authoritative contribution contract. Check every requirement before review:

- the branch uses the documented pattern for its task type: `dev/` for a new
  feature, `fix/` for a bug fix, `perf/` for a performance optimization or
  other enhancement, or `doc/` for documentation;
- every commit header follows `[<type>]: <subject>` with an allowed `+`, `-`,
  `=`, or `~` type;
- the contributor has signed or will complete the CLA before merge;
- the change follows the Nginx-derived XQUIC code style;
- the full test suite and sufficient relevant tests pass;
- required continuous-integration checks pass before merge;
- the branch is rebased on its current base, and review-fix commits are
  squashed before merge; and
- an issue-closing pull request contains the exact `Fixes: #<number>` line.

Documentation-only changes follow the same review process. They may use the
documented runtime-test exemption, but must provide their applicable link,
format, and command-syntax evidence.

Do not copy this internal checklist into the pull request. Publish only:

- `Overall: Passed` when every item passes, otherwise `Pending` or
  `Not passed`;
- `Local regression: Complete` when the required local gate passes, otherwise
  list only the failing case IDs and their concise behavior;
- `CI: Complete` when all required checks pass, otherwise list only pending or
  failed checks.

## Mechanism

Explain the behavioral or project mechanism being changed and why the new
mechanism is correct. Avoid a file-by-file change inventory. For QUIC, HTTP/3,
QPACK, or MoQ behavior, cite the exact RFC or draft section number beside the
mechanism. For non-protocol work, state that no RFC applies.

When the pull request closes an issue, retain the exact standalone
`Fixes: #<number>` line required by `CONTRIBUTING.md`.

## Validation Cases

The full validation gate remains mandatory. Its local record retains exact
commands, the CUnit `Total/Ran/Passed/Failed` summary, unit-test names, case
names, logs, and reservation snapshots. Do not copy those details into the
pull request.

In the pull request, describe paired client-to-server coverage with one line
per case:

```text
<case ID> — <concise behavior proved by the case>
```

Include the happy path and abnormal path. Do not include commands, unit-test
function names, `case_print_result` names, logs, namespace ranges, tested
commit SHA, or successful reservation-scan details. Those are discoverable in
the change and its validation artifacts.

If runtime cases do not apply, state the reason in one line. For a failed local
gate, list only each failing case ID and its concise behavior under
`Local regression`; use a short suite-level description when the failure has
no client-to-server case ID.

## Case-ID Coordination

New case IDs must still pass the allocation and open-PR reservation procedure
in the [validation specification](validation.md#client-to-server-case-id-namespace).
Keep its detailed snapshots out of a passing PR body. A conflict makes local
regression incomplete and must be named concisely as a blocker.

Publish new-case PRs and case-ID-changing updates in draft until the
post-publication scan passes. If two open PRs claim the same ID, the lower PR
number keeps it. The later PR must remain draft, reallocate, and rerun the
complete validation gate.

## Aggregate Gate

Use exactly one aggregate `CONTRIBUTING.md` section. Mark local regression and
CI `Complete` when they pass. If either has not run, is pending, or failed,
state that status and list only the incomplete checks or concise failed cases.
Mark `Overall: Passed` only when the complete internal contribution checklist,
local regression, CI, and case-ID coordination all pass. Do not expand the
internal checklist into additional PR fields.

Submit a new code PR as draft after local validation. Then run the
[`xquic-pr-pre-review` skill](../skills/xquic-pr-pre-review/SKILL.md) against
the published PR's exact base and head. Require `pre_review_result: true` from
all five sections before ready-for-review state, and keep
`~/build/harness/pr-review-<number>/pr-review-<number>.md` and every sibling
abnormal-case artifact local and uncommitted. The review directory is a gate
input and a reusable input to the next iteration; do not copy it into the
concise PR body. A changed published head invalidates the report, and retained
cases must be rerun against the new head.

## Scope Rules

- Do not mix harness construction with unrelated product fixes unless the
  harness change is required to validate the fix.
- Do not add issue-specific build directories, targets, options, or CI jobs.
- Keep generated and diagnostic artifacts out of source control unless they
  are stable, intentionally reviewable deliverables.
- A failure discovered during validation is fixed before the pull request is
  presented as ready.
- Keep a production code pull request in draft while paired coverage is
  missing, the complete local unit suite fails, or either relevant case test
  fails.
- Keep the later-numbered pull request in draft while it duplicates a case ID
  reserved by another open pull request.
- Do not turn the PR body into a validation log; preserve detailed evidence in
  its source artifact and publish the concise aggregate.
