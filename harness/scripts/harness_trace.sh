#!/bin/bash
#
# Initialize ignored task-local harness evidence directories.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMMAND="${1:-}"
TASK_ID="${2:-}"

usage()
{
    echo "usage: $0 init <task-id>" >&2
}

safe_task_id()
{
    local value="$1"

    if [[ ! "${value}" =~ ^[A-Za-z0-9._-]+$ ]]; then
        echo "task-id may contain only letters, numbers, dot, underscore, and hyphen" >&2
        exit 2
    fi
}

write_if_missing()
{
    local path="$1"
    local title="$2"

    if [[ -e "${path}" ]]; then
        return
    fi

    {
        echo "# ${title}"
        echo ""
        echo "- status: pending"
    } > "${path}"
}

case "${COMMAND}" in
    init)
        if [[ -z "${TASK_ID}" ]]; then
            usage
            exit 2
        fi
        safe_task_id "${TASK_ID}"

        RUN_DIR="${ROOT_DIR}/build/harness/runs/${TASK_ID}"
        mkdir -p "${RUN_DIR}"

        write_if_missing "${RUN_DIR}/task.md" "Task"
        write_if_missing "${RUN_DIR}/read-files.md" "Read Files"
        write_if_missing "${RUN_DIR}/detect.md" "Detection"
        write_if_missing "${RUN_DIR}/failures.md" "Failures"
        write_if_missing "${RUN_DIR}/evidence.md" "Evidence"
        if [[ ! -e "${RUN_DIR}/commands.log" ]]; then
            : > "${RUN_DIR}/commands.log"
        fi

        echo "${RUN_DIR}"
        ;;
    *)
        usage
        exit 2
        ;;
esac
