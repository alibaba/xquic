#!/bin/bash
#
# Test pre-push behavior with a fake validator; setup tests hook registration.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HOOK="${ROOT_DIR}/scripts/hooks/pre-push"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/xquic-pre-push-test.XXXXXX")"
FAKE_REPO="${TEST_DIR}/repo"

cleanup()
{
    rm -rf "${TEST_DIR}"
}

fail()
{
    echo "pre_push_hook_test: $*" >&2
    exit 1
}

run_hook()
{
    (
        cd "${FAKE_REPO}"
        XQC_TEST_NAME=focused "${HOOK}"
    )
}

expect_hook_failure()
{
    local message="$1"

    if run_hook >/dev/null 2>&1; then
        fail "${message}"
    fi
}

trap cleanup EXIT HUP INT TERM

mkdir -p "${FAKE_REPO}/scripts"
git -C "${FAKE_REPO}" init -q

cat > "${FAKE_REPO}/scripts/validate.sh" <<'EOF'
#!/bin/bash

if [[ "$1" != "full" ]]; then
    exit 8
fi

if [[ "${XQC_BUILD_DIR:-}" != "build" ]]; then
    exit 9
fi

if [[ -n "${XQC_TEST_NAME:-}" ]]; then
    exit 10
fi

printf '%s\n' "${FAKE_VALIDATION_OUTPUT:-[       OK ] fake.case}"
exit "${FAKE_VALIDATION_STATUS:-0}"
EOF
chmod +x "${FAKE_REPO}/scripts/validate.sh"

run_hook >/dev/null || fail "successful validation was rejected"

FAKE_VALIDATION_OUTPUT='[     FAIL ] fake.case' \
    expect_hook_failure "case failure marker was accepted"
FAKE_VALIDATION_OUTPUT='>>>>>>>> pass:0' \
    expect_hook_failure "legacy failure marker was accepted"
FAKE_VALIDATION_STATUS=7 \
    expect_hook_failure "validation command failure was accepted"

echo "pre_push_hook_test: all checks passed"
