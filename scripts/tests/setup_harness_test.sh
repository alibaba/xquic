#!/bin/bash
#
# Test the setup registration contract; hook behavior has a separate test.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SETUP_SCRIPT="${ROOT_DIR}/scripts/setup_harness.sh"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/xquic-harness-test.XXXXXX")"

cleanup()
{
    rm -rf "${TEST_DIR}"
}

fail()
{
    echo "setup_harness_test: $*" >&2
    exit 1
}

assert_link()
{
    local target="$1"
    local expected="$2"

    [[ -L "${target}" ]] || fail "missing link: ${target}"
    [[ "$(readlink "${target}")" == "${expected}" ]] \
        || fail "wrong link target: ${target}"
}

assert_entry_count()
{
    local directory="$1"
    local expected="$2"
    local actual

    actual="$(
        find "${directory}" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' '
    )"
    [[ "${actual}" == "${expected}" ]] \
        || fail "unexpected entry count in ${directory}: ${actual}"
}

run_setup()
{
    "${SETUP_SCRIPT}" \
        --skills-dir "${SKILLS_DIR}" \
        --pipelines-dir "${PIPELINES_DIR}" \
        --hooks-dir "${HOOKS_DIR}" \
        --install-pre-push-hook
}

trap cleanup EXIT HUP INT TERM

SKILLS_DIR="${TEST_DIR}/positive/skills"
PIPELINES_DIR="${TEST_DIR}/positive/pipelines"
HOOKS_DIR="${TEST_DIR}/positive/hooks"
EXPECTED_SKILLS=(
    issue-check
    issue-submit
    validate
    xquic-pr-pre-review
    xquic-pr-formatting
)

run_setup

for skill_name in "${EXPECTED_SKILLS[@]}"; do
    assert_link "${SKILLS_DIR}/${skill_name}" \
        "${ROOT_DIR}/harness/skills/${skill_name}"
done

assert_entry_count "${SKILLS_DIR}" "${#EXPECTED_SKILLS[@]}"
assert_link "${PIPELINES_DIR}/dev-pipeline.md" \
    "${ROOT_DIR}/harness/pipelines/dev-pipeline.md"
assert_entry_count "${PIPELINES_DIR}" 1
assert_link "${HOOKS_DIR}/pre-push" \
    "${ROOT_DIR}/scripts/hooks/pre-push"
assert_entry_count "${HOOKS_DIR}" 1

run_setup

COLLISION_DIR="${TEST_DIR}/collision"
mkdir -p "${COLLISION_DIR}/skills"
printf 'preserve me\n' > "${COLLISION_DIR}/skills/issue-check"

if "${SETUP_SCRIPT}" \
    --skills-dir "${COLLISION_DIR}/skills" \
    --pipelines-dir "${COLLISION_DIR}/pipelines"
then
    fail "existing skill collision unexpectedly succeeded"
fi

grep -Fx 'preserve me' "${COLLISION_DIR}/skills/issue-check" >/dev/null \
    || fail "existing path was modified"

echo "setup_harness_test: all checks passed"
