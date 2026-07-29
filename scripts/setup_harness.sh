#!/bin/bash
#
# Register repository-owned harness skills, pipelines, and optional hooks.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS_DIR="${ROOT_DIR}/harness"
AGENT_DIR="${ROOT_DIR}/.agents"
SKILLS_DIR="${XQUIC_HARNESS_SKILLS_DIR:-${AGENT_DIR}/skills}"
PIPELINES_DIR="${XQUIC_HARNESS_PIPELINES_DIR:-${AGENT_DIR}/pipelines}"
HOOKS_DIR=""
INSTALL_PRE_PUSH_HOOK=0

usage()
{
    cat <<'EOF'
usage: ./scripts/setup_harness.sh [options]

Register the canonical XQUIC harness using symbolic links.

Options:
  --skills-dir DIR        Override the skill discovery directory.
  --pipelines-dir DIR     Override the pipeline discovery directory.
  --install-pre-push-hook Install the optional complete validation hook.
  --hooks-dir DIR         Override the Git hooks directory for hook install.
  -h, --help              Show this help.

Environment:
  XQUIC_HARNESS_SKILLS_DIR
  XQUIC_HARNESS_PIPELINES_DIR
EOF
}

absolute_path()
{
    local path="$1"

    if [[ "${path}" == /* ]]; then
        printf '%s\n' "${path}"

    else
        printf '%s\n' "${ROOT_DIR}/${path}"
    fi
}

register_link()
{
    local source="$1"
    local target="$2"
    local current

    mkdir -p "$(dirname "${target}")"

    if [[ -L "${target}" ]]; then
        current="$(readlink "${target}")"

        if [[ "${current}" == "${source}" ]]; then
            echo "registered: ${target}"
            return
        fi

        echo "refusing to replace link: ${target} -> ${current}" >&2
        return 1
    fi

    if [[ -e "${target}" ]]; then
        echo "refusing to replace existing path: ${target}" >&2
        return 1
    fi

    ln -s "${source}" "${target}"
    echo "registered: ${target} -> ${source}"
}

default_hooks_dir()
{
    local path

    path="$(git -C "${ROOT_DIR}" rev-parse --git-path hooks)"
    absolute_path "${path}"
}

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --skills-dir)
            [[ "$#" -ge 2 ]] || {
                echo "--skills-dir requires a value" >&2
                exit 2
            }
            SKILLS_DIR="$2"
            shift 2
            ;;
        --pipelines-dir)
            [[ "$#" -ge 2 ]] || {
                echo "--pipelines-dir requires a value" >&2
                exit 2
            }
            PIPELINES_DIR="$2"
            shift 2
            ;;
        --install-pre-push-hook)
            INSTALL_PRE_PUSH_HOOK=1
            shift
            ;;
        --hooks-dir)
            [[ "$#" -ge 2 ]] || {
                echo "--hooks-dir requires a value" >&2
                exit 2
            }
            HOOKS_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit
            ;;
        *)
            echo "unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

SKILLS_DIR="$(absolute_path "${SKILLS_DIR}")"
PIPELINES_DIR="$(absolute_path "${PIPELINES_DIR}")"

for skill_file in "${HARNESS_DIR}"/skills/*/SKILL.md; do
    skill_dir="${skill_file%/SKILL.md}"
    skill_name="${skill_dir##*/}"
    register_link "${skill_dir}" "${SKILLS_DIR}/${skill_name}"
done

for pipeline_file in "${HARNESS_DIR}"/pipelines/*.md; do
    pipeline_name="${pipeline_file##*/}"
    register_link "${pipeline_file}" \
        "${PIPELINES_DIR}/${pipeline_name}"
done

if [[ "${INSTALL_PRE_PUSH_HOOK}" -eq 1 ]]; then
    if [[ -z "${HOOKS_DIR}" ]]; then
        HOOKS_DIR="$(default_hooks_dir)"

    else
        HOOKS_DIR="$(absolute_path "${HOOKS_DIR}")"
    fi

    register_link "${ROOT_DIR}/scripts/hooks/pre-push" \
        "${HOOKS_DIR}/pre-push"
fi

echo "xquic harness setup complete"
