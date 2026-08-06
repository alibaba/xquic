#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
IMQUIC_ROOT=${1:-}
IMQUIC_EXPECTED_HEAD=1f4cbf8a638b80ef40f251fe9787b29f192b0cee
IMQUIC_PATCH="${ROOT_DIR}/moq/tests/patches/imquic-draft18-lifecycle.patch"
IMQUIC_EXPECTED_PATCH_SHA256=f54d71540cd8a3ffe381862a7bc5643d63beaf5b8fb2eec516bb7bfb5547aab8

if [[ -z "${IMQUIC_ROOT}" || $((($# - 1) % 2)) -ne 0 ]]; then
    echo "usage: $0 IMQUIC_ROOT [ROLE BINARY]..." >&2
    exit 2
fi

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

expected_binary_path() {
    case "$1" in
        relay)        printf '%s/examples/imquic-moq-relay\n' "${IMQUIC_ROOT}" ;;
        publisher)    printf '%s/examples/imquic-moq-pub\n' "${IMQUIC_ROOT}" ;;
        subscriber)   printf '%s/examples/imquic-moq-sub\n' "${IMQUIC_ROOT}" ;;
        interop-test) printf '%s/examples/imquic-moq-interop-test\n' "${IMQUIC_ROOT}" ;;
        *)
            echo "unknown imquic binary role: $1" >&2
            return 2
            ;;
    esac
}

imquic_head=$(git -C "${IMQUIC_ROOT}" rev-parse HEAD 2>/dev/null || true)
if [[ "${imquic_head}" != "${IMQUIC_EXPECTED_HEAD}" ]]; then
    echo "imquic HEAD mismatch: expected ${IMQUIC_EXPECTED_HEAD}, got ${imquic_head:-none}" >&2
    exit 2
fi

patch_sha256=$(sha256_file "${IMQUIC_PATCH}")
if [[ "${patch_sha256}" != "${IMQUIC_EXPECTED_PATCH_SHA256}" ]]; then
    echo "imquic patch SHA-256 mismatch: expected ${IMQUIC_EXPECTED_PATCH_SHA256}, got ${patch_sha256}" >&2
    exit 2
fi
if ! git -C "${IMQUIC_ROOT}" apply --reverse --check "${IMQUIC_PATCH}"; then
    echo "imquic lifecycle patch is not fully applied" >&2
    exit 2
fi

INDEX_DIR=$(mktemp -d "${TMPDIR:-/tmp}/imquic-peer-index.XXXXXX")
trap 'rm -rf -- "${INDEX_DIR}"' EXIT
EXPECTED_INDEX="${INDEX_DIR}/expected.index"
ACTUAL_INDEX="${INDEX_DIR}/actual.index"

GIT_INDEX_FILE="${EXPECTED_INDEX}" \
    git -C "${IMQUIC_ROOT}" read-tree HEAD
GIT_INDEX_FILE="${EXPECTED_INDEX}" \
    git -C "${IMQUIC_ROOT}" apply --cached "${IMQUIC_PATCH}"
expected_tree=$(GIT_INDEX_FILE="${EXPECTED_INDEX}" \
    git -C "${IMQUIC_ROOT}" write-tree)

GIT_INDEX_FILE="${ACTUAL_INDEX}" \
    git -C "${IMQUIC_ROOT}" read-tree HEAD
GIT_INDEX_FILE="${ACTUAL_INDEX}" \
    git -C "${IMQUIC_ROOT}" add -A -- .
actual_tree=$(GIT_INDEX_FILE="${ACTUAL_INDEX}" \
    git -C "${IMQUIC_ROOT}" write-tree)
if [[ "${actual_tree}" != "${expected_tree}" ]]; then
    echo "imquic source tree mismatch: expected ${expected_tree}, got ${actual_tree}" >&2
    exit 2
fi

printf 'peer_source_provenance|head:%s|patch_sha256:%s|tree:%s|state:patched-worktree\n' \
    "${imquic_head}" "${patch_sha256}" "${actual_tree}"

shift
# Keep binary evidence separate from the exact source-tree proof above.  The
# CI job establishes freshness by building this checkout immediately before
# running the interop scripts; local runs only record path and content hash.
while [[ $# -gt 0 ]]; do
    role=$1
    binary=$2
    expected_binary=$(expected_binary_path "${role}") || exit 2
    if [[ ! -x "${binary}" ]]; then
        echo "imquic ${role} binary not executable: ${binary}" >&2
        exit 2
    fi
    if [[ ! -x "${expected_binary}" ]]; then
        echo "expected imquic ${role} binary not executable: ${expected_binary}" >&2
        exit 2
    fi
    binary_real=$(realpath "${binary}") || exit 2
    expected_real=$(realpath "${expected_binary}") || exit 2
    if [[ "${binary_real}" != "${expected_real}" ]]; then
        echo "imquic ${role} binary path mismatch: expected ${expected_real}, got ${binary_real}" >&2
        exit 2
    fi
    printf 'peer_binary_observation|role:%s|path:%s|sha256:%s\n' \
        "${role}" "${binary_real}" "$(sha256_file "${binary_real}")"
    shift 2
done
