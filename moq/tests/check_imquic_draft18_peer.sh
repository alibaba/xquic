#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
IMQUIC_ROOT=${1:-}
IMQUIC_EXPECTED_HEAD=1f4cbf8a638b80ef40f251fe9787b29f192b0cee
IMQUIC_PATCH="${ROOT_DIR}/moq/tests/patches/imquic-draft18-lifecycle.patch"
IMQUIC_EXPECTED_PATCH_SHA256=f7148dc05c6a6a6009c77b32429c38211c790f81604a3bbc4e7ba86115a04e54

if [[ -z "${IMQUIC_ROOT}" ]]; then
    echo "usage: $0 IMQUIC_ROOT" >&2
    exit 2
fi

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
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

printf 'peer_provenance|head:%s|patch_sha256:%s|tree:%s|state:patched-worktree\n' \
    "${imquic_head}" "${patch_sha256}" "${actual_tree}"
