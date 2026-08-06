#!/bin/bash
#
# Shared helpers for endpoint case-test runners.

case_test_root()
{
    cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd
}

case_test_build_dir()
{
    local root="$1"
    local build_dir="${XQC_BUILD_DIR:-${root}/build}"

    if [[ "${build_dir}" != /* ]]; then
        build_dir="${root}/${build_dir}"
    fi

    printf '%s\n' "${build_dir}"
}

case_test_prepare_work_dir()
{
    local build_dir="$1"
    local work_dir="$2"

    mkdir -p "${work_dir}"

    if [[ -f "${build_dir}/server.key" && ! -e "${work_dir}/server.key" ]]; then
        ln -s "${build_dir}/server.key" "${work_dir}/server.key"
    fi

    if [[ -f "${build_dir}/server.crt" && ! -e "${work_dir}/server.crt" ]]; then
        ln -s "${build_dir}/server.crt" "${work_dir}/server.crt"
    fi
}
