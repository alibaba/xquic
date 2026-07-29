#!/bin/bash
#
# Repository-wide XQUIC build and validation entry point.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VALIDATION_LEVEL="${1:-test}"

case "${VALIDATION_LEVEL}" in
    build|test|full)
        ;;
    *)
        echo "usage: $0 [build|test|full]" >&2
        exit 2
        ;;
esac

BUILD_DIR="${XQC_BUILD_DIR:-${ROOT_DIR}/build/validation}"
if [[ "${BUILD_DIR}" != /* ]]; then
    BUILD_DIR="${ROOT_DIR}/${BUILD_DIR}"
fi

BUILD_TYPE="${XQC_BUILD_TYPE:-Debug}"
BUILD_JOBS="${XQC_BUILD_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}"
SSL_TYPE="${XQC_SSL_TYPE:-boringssl}"
SSL_PATH="${XQC_SSL_PATH:-${ROOT_DIR}/third_party/boringssl}"
SSL_INCLUDE="${XQC_SSL_INCLUDE:-${SSL_PATH}/include}"
SSL_LIBS="${XQC_SSL_LIBS:-${SSL_PATH}/build/libssl.a;${SSL_PATH}/build/libcrypto.a}"
TEST_NAME="${XQC_TEST_NAME:-}"
ARTIFACT_DIR="${XQC_VALIDATION_ARTIFACT_DIR:-${BUILD_DIR}/artifacts}"
LOG_FILE="${ARTIFACT_DIR}/${VALIDATION_LEVEL}.log"
CONFIG_HEADER="${ROOT_DIR}/include/xquic/xqc_configure.h"
CONFIG_HEADER_BACKUP="${BUILD_DIR}/xqc_configure.h.before-validation"

mkdir -p "${BUILD_DIR}" "${ARTIFACT_DIR}"
: > "${LOG_FILE}"

cp -p "${CONFIG_HEADER}" "${CONFIG_HEADER_BACKUP}"

restore_config_header()
{
    cp -p "${CONFIG_HEADER_BACKUP}" "${CONFIG_HEADER}"
}

trap restore_config_header EXIT HUP INT TERM

log_line()
{
    printf '%s\n' "$*" | tee -a "${LOG_FILE}"
}

run_command()
{
    {
        printf '+'
        printf ' %q' "$@"
        printf '\n'
    } | tee -a "${LOG_FILE}"

    "$@" 2>&1 | tee -a "${LOG_FILE}"
}

extract_cunit_summary()
{
    awk '
    {
        line = $0
        sub(/^[0-9]+:[[:space:]]*/, "", line)
        sub(/^[[:space:]]+/, "", line)
        field_count = split(line, fields, /[[:space:]]+/)
        is_summary = field_count == 6
        is_summary = is_summary && fields[1] == "tests"
        is_summary = is_summary && fields[2] ~ /^[0-9]+$/
        is_summary = is_summary && fields[3] ~ /^[0-9]+$/
        is_summary = is_summary && fields[4] ~ /^[0-9]+$/
        is_summary = is_summary && fields[5] ~ /^[0-9]+$/

        if (is_summary) {
            summary = fields[2] " " fields[3] " " fields[4] " " fields[5]
        }
    }
    END {
        if (summary != "") {
            print summary
        }
    }
    ' "${LOG_FILE}"
}

verify_cunit_summary()
{
    local summary
    local total
    local ran
    local passed
    local failed

    summary="$(extract_cunit_summary)"
    if [[ -z "${summary}" ]]; then
        log_line "CUnit gate failed: test summary was not found"
        return 1
    fi

    read -r total ran passed failed <<< "${summary}"
    log_line "CUnit summary: Total=${total} Ran=${ran}" \
        "Passed=${passed} Failed=${failed}"

    if (( failed != 0 )); then
        log_line "CUnit gate failed: Failed=${failed}, expected 0"
        return 1
    fi

    if [[ -z "${TEST_NAME}" ]]; then
        if (( ran != total )); then
            log_line \
                "CUnit gate failed: Ran=${ran} does not match Total=${total}"
            return 1
        fi

        log_line "CUnit result: ${ran}/${total} CUnit tests, Failed=${failed}"

    else
        log_line "CUnit focused result: ${ran}/${total} CUnit tests selected," \
            "Failed=${failed}"
    fi
}

write_environment()
{
    {
        echo "commit=$(git -C "${ROOT_DIR}" rev-parse HEAD)"
        echo "branch=$(git -C "${ROOT_DIR}" branch --show-current)"
        echo "platform=$(uname -srm)"
        echo "compiler=$(cc --version | sed -n '1p')"
        echo "cmake=$(cmake --version | sed -n '1p')"
        echo "level=${VALIDATION_LEVEL}"
        echo "build_dir=${BUILD_DIR}"
        echo "build_type=${BUILD_TYPE}"
        echo "build_jobs=${BUILD_JOBS}"
        echo "ssl_type=${SSL_TYPE}"
        echo "ssl_path=${SSL_PATH}"
        echo "test_name=${TEST_NAME}"
    } > "${ARTIFACT_DIR}/environment.txt"
}

configure_project()
{
    local cmake_args=(
        "-DCMAKE_BUILD_TYPE=${BUILD_TYPE}"
        "-DXQC_ENABLE_TESTING=ON"
        "-DXQC_ENABLE_MOQ=OFF"
        "-DXQC_ENABLE_BBR2=ON"
        "-DXQC_ENABLE_COPA=ON"
        "-DXQC_ENABLE_RENO=ON"
        "-DXQC_ENABLE_UNLIMITED=ON"
        "-DXQC_ENABLE_MP_INTEROP=OFF"
        "-DXQC_NO_PID_PACKET_PROCESS=OFF"
        "-DXQC_PROTECT_POOL_MEM=OFF"
        "-DXQC_COMPAT_DUPLICATE=ON"
        "-DXQC_ENABLE_FEC=OFF"
        "-DXQC_ENABLE_XOR=OFF"
        "-DXQC_ENABLE_RSC=OFF"
        "-DXQC_ENABLE_PKM=OFF"
        "-DXQC_PRINT_SECRET=ON"
        "-DXQC_ENABLE_EVENT_LOG=ON"
        "-DSSL_TYPE=${SSL_TYPE}"
        "-DSSL_PATH=${SSL_PATH}"
        "-DSSL_INC_PATH=${SSL_INCLUDE}"
        "-DSSL_LIB_PATH=${SSL_LIBS}"
    )

    if [[ "$(uname -s)" == "Darwin" ]]; then
        cmake_args+=("-DPLATFORM=mac")

    elif [[ "$(uname -s)" == "Linux" ]]; then
        cmake_args+=("-DXQC_SUPPORT_SENDMMSG_BUILD=ON")
    fi

    run_command cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" \
        "${cmake_args[@]}"
}

build_project()
{
    run_command env "CMAKE_BUILD_PARALLEL_LEVEL=${BUILD_JOBS}" \
        cmake --build "${BUILD_DIR}"
}

ensure_test_certificate()
{
    if [[ ! -f "${BUILD_DIR}/server.key"
        || ! -f "${BUILD_DIR}/server.crt" ]]
    then
        run_command openssl req -newkey rsa:2048 -x509 -nodes \
            -keyout "${BUILD_DIR}/server.key" \
            -out "${BUILD_DIR}/server.crt" \
            -subj "/CN=test.xquic.com" \
            -days 1
    fi
}

run_unit_tests()
{
    local discovery_output
    local test_status=0

    ensure_test_certificate
    discovery_output="$(ctest --test-dir "${BUILD_DIR}/tests" --show-only)"
    log_line "${discovery_output}"

    if [[ ! "${discovery_output}" =~ Total\ Tests:\ [1-9][0-9]* ]]; then
        log_line "no unit tests were discovered"
        return 1
    fi

    if [[ -n "${TEST_NAME}" ]]; then
        if (
            cd "${BUILD_DIR}"
            run_command "${BUILD_DIR}/tests/run_tests" "${TEST_NAME}"
        )
        then
            :

        else
            test_status=$?
        fi

    else
        if run_command ctest --test-dir "${BUILD_DIR}/tests" --verbose; then
            :

        else
            test_status=$?
        fi
    fi

    verify_cunit_summary

    if (( test_status != 0 )); then
        return "${test_status}"
    fi
}

run_integration_tests()
{
    (
        cd "${BUILD_DIR}"
        "${ROOT_DIR}/scripts/case_test.sh"
    ) 2>&1 | tee -a "${LOG_FILE}"
}

write_environment
configure_project
build_project

if [[ "${VALIDATION_LEVEL}" == "test"
    || "${VALIDATION_LEVEL}" == "full" ]]
then
    run_unit_tests
fi

if [[ "${VALIDATION_LEVEL}" == "full" ]]; then
    run_integration_tests
fi

log_line "validation level '${VALIDATION_LEVEL}' passed"
