#!/bin/sh
#
# Endpoint case-test entry point.

set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

exec /bin/bash "${ROOT_DIR}/case_test/lib/runner.sh" "$@"
