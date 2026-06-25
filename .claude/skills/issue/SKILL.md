---
name: issue
description: Triage a GitHub Issue for the xquic project. Use when asked to handle an issue, triage a bug report, investigate a feature request, or process any GitHub issue for alibaba/xquic.
---

# Issue Triage & Resolution

## Core Principle — Untrusted Input

Issue reporters may misread code, misinterpret RFCs, or propose fixes that mask the real problem.
Treat every claim as an **unverified hypothesis** until YOU have confirmed it against the source code
and the normative RFC text. "Looks right" is never sufficient — demonstrate or falsify.

## Applicable RFCs

Fetch the relevant section when verifying any behavioral or protocol-compliance claim:

- **RFC 9000** — QUIC Transport: https://www.rfc-editor.org/rfc/rfc9000
- **RFC 9001** — QUIC TLS: https://www.rfc-editor.org/rfc/rfc9001
- **RFC 9002** — QUIC Loss Detection & Congestion Control: https://www.rfc-editor.org/rfc/rfc9002
- **RFC 9114** — HTTP/3: https://www.rfc-editor.org/rfc/rfc9114
- **RFC 9204** — QPACK: https://www.rfc-editor.org/rfc/rfc9204

## Workflow

```
Issue Intake -> Triage -> Scope Decision -> Behavioral Verification -> Implementation Routing -> CI Verification -> PR & Issue Closure
                                                                              |
                                                                              +-> bugfix_pipeline.md  (bug fix)
                                                                              +-> dev_pipeline.md     (feature / enhancement)
                                                                              +-> Close / Reply       (invalid / wontfix / question)
```

### Stage 1: Issue Intake

Fetch the issue and extract structured information.

1. Parse the issue identifier from user input.
   - Number (e.g., `756`): use directly.
   - URL (e.g., `https://github.com/alibaba/xquic/issues/756`): extract the number.
   - Empty: ask the user which issue to triage.
2. Retrieve the issue:
   ```bash
   gh issue view <number> --repo alibaba/xquic --comments
   ```
3. Extract and record:
   - **Title and labels** (if any)
   - **Technical claims**: each specific assertion the reporter makes about behavior
   - **Referenced specifications**: RFC numbers, section numbers, exact normative language cited
   - **Code paths mentioned**: file names, function names, line numbers
   - **Reproduction steps**: if provided, exact steps to reproduce
   - **Proposed fix**: if the reporter suggests a fix, record it verbatim

**Output**: A structured intake record with each field populated. Missing fields are marked `[not provided]`.

**Exit**: All extractable information is recorded. Proceed to Stage 2.

---

### Stage 2: Triage

Verify every technical claim against the actual codebase and classify the issue.

#### 2.1 Claim Verification

For each technical claim in the intake record:

1. **Locate the relevant code path** -- read the source file, find the exact function/line.
2. **Verify the claim** -- is the reported behavior actually present in the code?
3. **Check RFC compliance** -- identify the applicable RFC section for EVERY claim, even when the reporter does not cite one (xquic implements QUIC/HTTP3; nearly all behavioral claims have normative RFC text -- see Applicable RFCs above). If the reporter cites a specific section, verify the citation is correct (reporters sometimes cite the wrong section or misquote normative text). Compare MUST/SHOULD/MAY language against the implementation. For claims where no RFC applies (pure implementation bugs, API ergonomics), note "No RFC applies".
4. **Aggregate behavior analysis** -- trace ALL control-flow paths that gate the reported behavior, not just the specific variable/flag the reporter highlights. A flag may have incorrect semantics while the aggregate system behavior remains correct due to other guards.
5. **Behavioral falsification** -- before marking a claim as "Confirmed", identify the specific input/state sequence that triggers the RFC-violating behavior in the CURRENT code. If no such sequence can be constructed (because other guards prevent it), the verdict is "Not Confirmed (behavior enforced by [mechanism])".
6. **Record the verdict**: Confirmed / Partially Confirmed / Not Confirmed / Cannot Verify.

**Verdict rules**:
- "Confirmed" requires a demonstrable path to incorrect behavior in the current code.
- "Partially Confirmed" means the code has incorrect semantics but behavior is correct due to other guards (may warrant cleanup but is NOT a bug fix).
- "Not Confirmed" means the current code is behaviorally correct regardless of internal naming/semantics.

#### 2.2 Classification

**Category**:

| Category | Criteria |
|----------|----------|
| Bug | Code behaves differently from specification or documented intent |
| Feature Request | Requests new functionality not currently implemented |
| Enhancement | Improvement to existing functionality (performance, API ergonomics) |
| Question | Asks about behavior without asserting a bug |
| Invalid | Based on incorrect assumptions, or the described behavior is correct |

**Severity** (for Bug and Enhancement only):

| Severity | Criteria |
|----------|----------|
| Critical | Security vulnerability, data corruption, crash in normal operation, protocol violation that breaks interop |
| Important | Incorrect behavior in edge cases, spec non-compliance that does not break interop, performance regression |
| Low | Cosmetic, documentation-only, or extremely unlikely edge case |

**RFC Compliance Level** (always assessed -- not only when the reporter cites an RFC):

| Level | Criteria |
|-------|----------|
| MUST violation | Code violates a MUST / MUST NOT requirement |
| SHOULD violation | Code violates a SHOULD / SHOULD NOT recommendation |
| MAY suggestion | Reporter suggests implementing a MAY-level option |
| No violation | Code is compliant; issue is based on misunderstanding |
| N/A | No RFC applies to this claim |

#### 2.3 Triage Report

Output a structured triage report. This is the core artifact of the pipeline.

```
## Triage Report: #<number>

### Classification
- **Category**: [Bug / Feature Request / Enhancement / Question / Invalid]
- **Severity**: [Critical / Important / Low / N/A]
- **RFC Compliance**: [MUST violation / SHOULD violation / MAY suggestion / No violation / N/A]

### Claim Verification

| # | Claim | Code Location | RFC Section | Verdict | Notes |
|---|-------|---------------|-------------|---------|-------|
| 1 | [claim text] | `file:line` | RFC 9000 S17.2 | Confirmed / Not Confirmed | [details] |
| 2 | ... | ... | ... or N/A | ... | ... |

### Recommendation
[Accept / Reject / Partial -- with reasoning for each claim]

### Scope Estimate
- Files likely affected: [list]
- Estimated complexity: [trivial / moderate / complex]
- Dependencies on other issues/PRs: [list or none]
```

**Exit**: Triage report is complete. Every claim has a verdict. **Present to user and wait for confirmation before proceeding.**

---

### Stage 3: Scope Decision

Determine what action to take based on the triage report.

#### 3.1 Action Decision

| Triage Outcome | Action |
|----------------|--------|
| All claims confirmed, bug | Fix required -- proceed to Stage 3.5 |
| Partial claims confirmed | Fix the confirmed subset -- proceed to Stage 3.5 |
| Feature request, accepted | Implement -- proceed to Stage 4 |
| Invalid / No violation | Reply to issue with evidence, close or label `wontfix` |
| Question | Reply with answer, close or label `question` |
| Duplicate | Link to existing issue, close as duplicate |

#### 3.2 Sub-Issue Splitting

When an issue contains **2 or more independently fixable bugs**:

1. Create a sub-issue for each independent bug:
   ```bash
   gh issue create --repo alibaba/xquic \
     --title "[Sub-issue of #<parent>] <specific bug title>" \
     --body "Parent issue: #<parent>\n\n<specific description and claims>"
   ```
2. Each sub-issue gets its own triage row and priority.
3. Establish dependency order if fixes must be applied sequentially.
4. Track sub-issues in the parent issue via a comment:
   ```bash
   gh issue comment <parent> --repo alibaba/xquic \
     --body "Split into sub-issues:\n- #<sub1> [title]\n- #<sub2> [title]\n..."
   ```

**Splitting rule**: Split when bugs touch different code paths or can be tested independently. Do NOT split when fixes are tightly coupled.

#### 3.3 Deduplication Check

1. Search for existing issues and PRs:
   ```bash
   gh issue list --repo alibaba/xquic --search "<key terms>" --state all
   gh pr list --repo alibaba/xquic --search "<key terms>" --state all
   ```
2. If already fixed in a merged PR, reply with the fix reference and close.
3. If an open PR addresses it, link to the PR and note in the triage report.

**Exit**: Action decision made. Sub-issues created if needed. No duplicates found. Proceed to Stage 3.5.

---

### Stage 3.5: Behavioral Verification (Mandatory for Bug Claims)

Before any implementation begins, verify that the current code actually exhibits the reported buggy behavior. Skip only for Feature Request / Enhancement.

**Agent requirement**: This stage MUST be executed using a dedicated verification agent (Task tool with `subagent_type=general-purpose`) for EACH claim marked "Confirmed".

#### 3.5.1 Construct a Falsification Scenario

For each claim marked "Confirmed" or "Partially Confirmed":

1. **Define the expected violation**: What specific RFC-violating behavior should occur? State it precisely.
2. **Trace the full execution path**: Starting from the entry point, trace every condition that must be true for the violation to occur. Include ALL guards on that path.
3. **Attempt to construct a trigger sequence**: Find concrete state values that would bypass all guards and trigger the violation.
4. **If no trigger sequence exists**: The claim is a **false positive**. Update the verdict to "Not Confirmed (behavior enforced by [mechanism])".

#### 3.5.2 Distinguish Semantic Bugs from Behavioral Bugs

| Type | Definition | Action |
|------|-----------|--------|
| **Behavioral bug** | Current code produces RFC-violating output/behavior observable by a peer | Fix required (proceed to Stage 4) |
| **Semantic bug** | Internal naming/state is misleading but behavior is correct | Enhancement only: cleanup/observability, NOT a bug fix |
| **No bug** | Reporter misread the code or RFC | Reply with evidence, close or label |

When a claim is downgraded from "behavioral bug" to "semantic bug":
- Reclassify from Bug to Enhancement.
- Adjust severity (typically Low).
- PR title/description must NOT use "fix:" prefix -- use "refactor:" or "improve:".
- Issue comment must clearly state: "The reported behavior is correct; this change improves internal clarity/observability only."

#### 3.5.3 Verification Agent Output

The verification agent must produce:

```
## Behavioral Verification Report

### Claim: [claim text]

**Expected violation**: [what RFC-violating behavior should occur]

**Execution path guards**:
1. [guard 1]: [condition] at [file:line]
2. [guard 2]: [condition] at [file:line]
...

**Trigger sequence**: [concrete state values that would trigger violation, OR "none found"]

**Verdict**: Behavioral bug / Semantic bug / False positive

**Evidence**: [specific code path analysis showing why the violation can/cannot occur]
```

**Exit**: All "Confirmed" claims have been behaviorally verified or reclassified. **Present the Behavioral Verification Report to user. If reclassification occurred, get confirmation before proceeding.** Proceed to Stage 4.

---

### Stage 4: Implementation Routing

Route each actionable item to the appropriate pipeline. This stage does NOT define implementation steps -- it delegates to existing pipelines.

#### Routing Rules

| Item Type | Target Pipeline | Branch Naming |
|-----------|----------------|---------------|
| Single bug fix | `docs_ai/bugfix_pipeline.md` | `issue-<number>-<short-desc>` |
| Multiple bug fixes (split) | `docs_ai/bugfix_pipeline.md` per sub-issue | `issue-<sub-number>-<short-desc>` |
| Feature / Enhancement | `docs_ai/dev_pipeline.md` | `issue-<number>-<short-desc>` |
| Mixed (bug + feature) | Split first (Stage 3.2), then route individually | per sub-issue |

#### Fork Remote Setup

Before creating branches, ensure the `fork` remote is configured:

```bash
git remote get-url fork 2>/dev/null || \
  git remote add fork git@github.com:cherylsy/xquic.git
```

Remotes:
```
origin  -> git@github.com:alibaba/xquic.git   (upstream, read-only for pushes)
fork    -> git@github.com:cherylsy/xquic.git   (push target for issue branches)
```

#### Branch & Worktree Creation

Each issue gets an **isolated worktree** to enable parallel work:

```bash
git fetch origin main
git worktree add ../xquic-issue-<number> -b issue-<number>-<short-desc> origin/main
```

Branch name conventions:
- Use the issue number (or sub-issue number for splits).
- `<short-desc>`: 2-4 words, lowercase, hyphen-separated (e.g., `fix-stateless-reset-len`).
- Example: `issue-756-qpack-huffman-fix`.

Worktree conventions:
- Directory: `../xquic-issue-<number>` (sibling to main project root).
- One worktree per issue; multiple issues can run in parallel.
- All implementation work happens inside the worktree directory.

#### Execution

1. `cd ../xquic-issue-<number>` -- enter the worktree.
2. Read the target pipeline document in full before starting.
3. Follow that pipeline's stages in order.
4. The triage report from Stage 2 serves as the "Bug Report" (bugfix_pipeline Stage 1) or "Requirement Analysis" (dev_pipeline Stage 1).
5. For split issues, process in priority order (Critical > Important > Low).
6. Push to fork when ready: `git push fork issue-<number>-<short-desc>`.

#### No-Op Detection (Post-Implementation Gate)

After implementation is complete, before pushing or creating the PR, answer:

1. **Does this change introduce new control-flow gating that was absent before?**
2. **Or does it only add logging, observability flags, or comments?**

If the answer is (2) only:
- Re-evaluate whether the original claim was a behavioral bug or a semantic/observability issue.
- If reclassified: update commit message prefix from `fix:` to `refactor:` or `improve:`.
- Update PR description to accurately reflect the change nature.

**Exit**: All routed items have completed their respective pipelines. Proceed to Stage 4.5.

---

### Stage 4.5: CI Verification

After implementation is complete and pushed to the fork, verify that the GitHub Actions CI pipeline passes on the PR.

#### CI Jobs (from `.github/workflows/build.yml`)

| Job | Platform | Scope | Pass Criteria |
|-----|----------|-------|---------------|
| `build-ubuntu` | ubuntu-latest | Build + Unit Tests + Case Tests + Coverage | All unit tests pass, all case tests pass |
| `build-macos` | macos-latest | Build only | Compilation succeeds |

Additional checks (non-blocking but should be green):
- `Analyze` (CodeQL security analysis)
- `Codacy Static Code Analysis`
- `license/cla` (Contributor License Agreement)

#### 4.5.1 Trigger CI

CI is triggered automatically when a PR is created against `main`. Push additional fixes:
```bash
git push fork issue-<number>-<short-desc>
```

#### 4.5.2 Monitor CI Results

```bash
gh pr checks <pr-number> --repo alibaba/xquic
gh pr checks <pr-number> --repo alibaba/xquic --watch --fail-fast
```

For long CI runs, use a background task and continue other work.

#### 4.5.3 Interpret Results

**All checks pass**: Proceed to Stage 5.

**Test failure introduced by this PR**:
1. Identify the failing test:
   ```bash
   gh run view <run-id> --repo alibaba/xquic --log-failed
   ```
2. Determine if caused by your changes (compare with `main` branch CI).
3. If caused by your changes: fix, push, and re-verify.

**Pre-existing test failure** (also fails on `main`):
1. Verify:
   ```bash
   gh run list --repo alibaba/xquic --branch main --limit 3
   gh run view <main-run-id> --repo alibaba/xquic --log-failed
   ```
2. Document in PR description: `Note: <test_name> failure is pre-existing on main (see run #<id>).`
3. Proceed to Stage 5.

**Distinguish unit test failures from case test (e2e) failures**:

CI `build-ubuntu` runs TWO test phases sequentially:
1. **Unit tests** (`run_tests` binary via CTest) -- log pattern: `[  FAILED  ] <suite>.<test_name>`
2. **Case tests** (`scripts/case_test.sh`) -- log pattern: `<test_name> ...>>>>>>>> pass:0`

#### 4.5.3a Local Case Test Reproduction

When CI case tests fail, reproduce locally using `/validate`:

```bash
# Full local validation (in worktree)
cd <worktree> && bash scripts/xqc_validate.sh --all

# Or targeted: just build + unit tests
bash scripts/xqc_validate.sh --quick

# Or just integration tests
bash scripts/xqc_validate.sh --integration
```

For running individual case tests, see `.claude/skills/validate/SKILL.md` (E2E Case Catalog and targeted test template).

macOS limitations:
- macOS CI only runs build, NOT case tests.
- `xqc_validate.sh` auto-sets `EVENT_NOKQUEUE=1` on macOS.
- The definitive test environment is Ubuntu.

#### 4.5.4 CI Verification Checklist

- [ ] `build-ubuntu`: Unit tests pass (or failures are pre-existing on `main`)
- [ ] `build-ubuntu`: Case tests pass
- [ ] `build-macos`: Build succeeds
- [ ] Any new test failures are documented and attributed
- [ ] If failures were introduced, they have been fixed and CI re-run passes

**Exit**: All CI checks green (or documented as pre-existing). Proceed to Stage 5.

---

### Stage 5: PR & Issue Closure

Create the PR from the fork, link it to the issue, and close the loop.

#### 5.1 Push to Fork

Commit issue fixes with the repository's historical bracket-prefix style:

```bash
git commit -m "[+] fix issue #<issue-number> <concise lowercase description>"
```

When a PR number is already known and the commit is being amended after PR creation, append it in the same style:

```bash
git commit --amend -m "[+] fix issue #<issue-number> <concise lowercase description> (#<pr-number>)"
```

Example:

```text
[+] fix issue #679 remove TRA_HS_CERTIFICATE_VERIFY_FAIL (0x1FE) from reserved CRYPTO_ERROR range (#809)
```

```bash
cd ../xquic-issue-<number>
git push fork issue-<number>-<short-desc>
```

#### 5.2 PR Creation (Fork -> Upstream)

```bash
gh pr create --repo alibaba/xquic \
  --head "cherylsy:issue-<number>-<short-desc>" \
  --base main \
  --title "<concise fix description>" \
  --body "$(cat <<'EOF'
## Summary
Fixes #<issue-number>

<1-3 bullet points describing what was changed and why>

## Claim Resolution

| # | Claim from Issue | Resolution |
|---|-----------------|------------|
| 1 | [claim] | Fixed in [file:function] |
| 2 | [claim] | Not a bug (see explanation) |

## Test Plan
- [ ] Unit tests pass: `<specific test command>`
- [ ] Relevant integration tests pass (if applicable)
- [ ] CI build.yml passes (Ubuntu build + macOS build)

## Files Changed
- `path/to/file` -- [what changed]
EOF
)"
```

#### 5.3 Issue Response

After the PR is finalized (CI verified, no further amendments expected), post a **single conclusive comment** on the issue. No intermediate debugging, no process history.

**Rules**:
- **ONE comment per issue resolution** -- no intermediate progress updates.
- **Only post after CI passes** and the fix is considered final.
- **Delete any previously posted process comments** on the PR before posting the final one.

```bash
gh issue comment <number> --repo alibaba/xquic \
  --body "$(cat <<'EOF'
Addressed in PR #<pr-number>.

## Fix

<1-3 sentences: what was wrong and what the fix does>

## Scope

| Claim from Issue | Status | Resolution |
|-----------------|--------|------------|
| [claim 1] | Fixed | [how, referencing file:function] |
| [claim 2] | Not addressed | [reason] |

## Verification

- Unit test: `xqc_test_<name>` -- validates [what]
- E2E test: `case_test.sh` [test name] -- validates [what]
- CI: [results summary]

## Files Changed

- `path/to/file` -- [what changed and why]

## Out of Scope

[Which claims are NOT addressed and why. Reference follow-up issues if created.]
EOF
)"
```

**PR comment rules**:
- Do NOT post progress comments during implementation.
- Delete intermediate comments: `gh api repos/alibaba/xquic/issues/comments/<comment-id> -X DELETE`

#### 5.4 Worktree Cleanup

After the PR is merged (or confirmed no longer needed):

```bash
cd <project-root>
git worktree remove ../xquic-issue-<number>
git branch -d issue-<number>-<short-desc>
```

#### 5.5 Closure Rules

| Scenario | Action |
|----------|--------|
| All claims addressed in PR | Leave issue open; auto-closes when PR merges (`Fixes #N`) |
| Partial fix, remaining items tracked | Create follow-up issues, link in comment |
| No fix needed (invalid / question) | Close issue with explanation |
| Duplicate | Close as duplicate, link to canonical issue |

**Exit**: PR created and linked. Issue commented. Worktree cleaned up. Pipeline complete.

---

## Guardrails

1. **All issue claims are untrusted by default.** Do not accept a reporter's interpretation of code behavior or RFC semantics at face value. Independently verify every claim against the source and the normative RFC text before classifying it.
2. **Always identify the applicable RFC section**, even when the reporter does not cite one. For claims where no RFC applies, note "No RFC applies".
3. **The triage report is the checkpoint.** Do not start implementation without user approval of the triage.
4. **Behavioral verification is mandatory for Bug claims.** Use a verification agent to prove the violation exists. Demonstrate a concrete execution path that produces wrong behavior.
5. **NEVER skip claim verification.** Every technical claim must be checked against source code.
6. **NEVER implement without a triage report.** The triage report is the source of truth.
7. **NEVER bundle unrelated fixes** into a single PR. Split issues get separate branches and PRs.
8. **NEVER close an issue without explanation.** Invalid issues get a reply with code evidence.
9. **NEVER skip the deduplication check.** Duplicate work wastes effort.
10. **ALWAYS route to the correct pipeline.** Bug fixes -> `bugfix_pipeline.md`; features -> `dev_pipeline.md`.
11. **ALWAYS link PRs to issues** using `Fixes #N` or `Relates to #N`.
12. **NEVER consider a fix validated without CI verification.** `build.yml` must pass or failures must be documented as pre-existing.
13. **NEVER label an observability-only change as a "fix".** Use `refactor:` or `improve:` prefix.
14. **Comment discipline**: Only post a single conclusive comment after CI verification. Delete any intermediate process comments.
15. **Never commit build-generated files**: Always check `git diff --cached -- include/xquic/xqc_configure.h` and unstage if present.
16. All GitHub operations use `gh` CLI, not direct API calls.
