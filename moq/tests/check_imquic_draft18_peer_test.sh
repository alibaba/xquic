#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
IMQUIC_SOURCE=${1:-}
PATCH_FILE="${ROOT_DIR}/moq/tests/patches/imquic-draft18-lifecycle.patch"
CHECKER="${ROOT_DIR}/moq/tests/check_imquic_draft18_peer.sh"

if [[ -z "${IMQUIC_SOURCE}" ]]; then
    echo "usage: $0 IMQUIC_SOURCE" >&2
    exit 2
fi

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/imquic-peer-check.XXXXXX")
trap 'rm -rf -- "${TMP_DIR}"' EXIT
PEER_DIR="${TMP_DIR}/imquic"
FAILURE_LOG="${TMP_DIR}/unexpected-source.log"

git clone --quiet --no-hardlinks "${IMQUIC_SOURCE}" "${PEER_DIR}"
git -C "${PEER_DIR}" checkout --quiet --detach \
    1f4cbf8a638b80ef40f251fe9787b29f192b0cee
git -C "${PEER_DIR}" apply "${PATCH_FILE}"
bash "${CHECKER}" "${PEER_DIR}" >/dev/null

printf '\n/* unexpected local peer modification */\n' \
    >>"${PEER_DIR}/src/stream.c"
if bash "${CHECKER}" "${PEER_DIR}" >"${FAILURE_LOG}" 2>&1; then
    echo "peer checker accepted an extra modification in a patched file" >&2
    exit 1
fi
if [[ $(<"${FAILURE_LOG}") != *"source tree mismatch"* ]]; then
    cat "${FAILURE_LOG}" >&2
    echo "peer checker failed for an unexpected reason" >&2
    exit 1
fi

echo "imquic peer exact-tree check: PASS"
