#!/bin/bash
#
# Repository-wide XQUIC build and validation entry point.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VALIDATION_LEVEL="test"
VALIDATION_LEVEL_SET=0
FEATURE_NAME=""
DRY_RUN=0
LIST_FEATURES=0

usage()
{
    echo "usage: $0 [build|test|full] [--feature <name>] [--dry-run] [--list-features]" >&2
}

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        build|test|full)
            if [[ "${VALIDATION_LEVEL_SET}" -eq 1 ]]; then
                usage
                exit 2
            fi
            VALIDATION_LEVEL="$1"
            VALIDATION_LEVEL_SET=1
            shift
            ;;
        --feature)
            if [[ "$#" -lt 2 ]]; then
                usage
                exit 2
            fi
            FEATURE_NAME="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --list-features)
            LIST_FEATURES=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage
            exit 2
            ;;
    esac
done

case "${VALIDATION_LEVEL}" in
    build|test|full)
        ;;
    *)
        echo "usage: $0 [build|test|full]" >&2
        exit 2
        ;;
esac

manifest_query()
{
    ruby - "${ROOT_DIR}" "${FEATURE_NAME}" "$1" <<'RUBY'
require "yaml"

root = ARGV.fetch(0)
feature_name = ARGV.fetch(1)
mode = ARGV.fetch(2)
manifest = YAML.load_file(File.join(root, "harness/spec/harness-manifest.yml"))

features = {}
manifest.fetch("modules", {}).each do |module_name, route|
  route.fetch("features", {}).each do |name, feature|
    features[name] = feature.merge("module" => module_name)
  end
end

case mode
when "list"
  puts features.keys.sort
when "flags"
  feature = features[feature_name]
  abort "unknown feature: #{feature_name}" unless feature
  puts feature.fetch("feature_flags", [])
when "units"
  feature = features[feature_name]
  abort "unknown feature: #{feature_name}" unless feature
  puts feature.fetch("validation", {}).fetch("unit", [])
else
  abort "unknown manifest query mode: #{mode}"
end
RUBY
}

if [[ "${LIST_FEATURES}" -eq 1 ]]; then
    manifest_query list
    exit 0
fi

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
FEATURE_CMAKE_ARGS=()
FEATURE_UNIT_TESTS=()

if [[ -n "${FEATURE_NAME}" ]]; then
    FEATURE_FLAGS="$(manifest_query flags)" || exit 2
    FEATURE_UNITS="$(manifest_query units)" || exit 2

    while IFS= read -r flag; do
        [[ -n "${flag}" ]] || continue
        FEATURE_CMAKE_ARGS+=("-D${flag}")
    done <<< "${FEATURE_FLAGS}"

    while IFS= read -r test_name; do
        [[ -n "${test_name}" ]] || continue
        FEATURE_UNIT_TESTS+=("${test_name}")
    done <<< "${FEATURE_UNITS}"
fi

print_plan()
{
    local arg

    echo "level=${VALIDATION_LEVEL}"
    echo "feature=${FEATURE_NAME:-<none>}"
    echo "build_dir=${BUILD_DIR}"
    echo "artifact_dir=${ARTIFACT_DIR}"
    echo "test_name=${TEST_NAME:-<all>}"
    if [[ "${#FEATURE_CMAKE_ARGS[@]}" -gt 0 ]]; then
        for arg in "${FEATURE_CMAKE_ARGS[@]}"; do
            echo "feature_cmake_arg=${arg}"
        done
    fi
    if [[ "${#FEATURE_UNIT_TESTS[@]}" -gt 0 ]]; then
        for arg in "${FEATURE_UNIT_TESTS[@]}"; do
            echo "feature_unit_test=${arg}"
        done
    fi
}

if [[ "${DRY_RUN}" -eq 1 ]]; then
    print_plan
    exit 0
fi

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
        echo "feature=${FEATURE_NAME}"
        printf 'feature_cmake_args='
        if [[ "${#FEATURE_CMAKE_ARGS[@]}" -gt 0 ]]; then
            printf '%s ' "${FEATURE_CMAKE_ARGS[@]}"
        fi
        echo ""
        printf 'feature_unit_tests='
        if [[ "${#FEATURE_UNIT_TESTS[@]}" -gt 0 ]]; then
            printf '%s ' "${FEATURE_UNIT_TESTS[@]}"
        fi
        echo ""
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
    if [[ "${#FEATURE_CMAKE_ARGS[@]}" -gt 0 ]]; then
        cmake_args+=("${FEATURE_CMAKE_ARGS[@]}")
    fi

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

    ensure_test_certificate
    discovery_output="$(ctest --test-dir "${BUILD_DIR}/tests" --show-only)"
    log_line "${discovery_output}"

    if [[ ! "${discovery_output}" =~ Total\ Tests:\ [1-9][0-9]* ]]; then
        log_line "no unit tests were discovered"
        return 1
    fi

    if [[ -n "${TEST_NAME}" ]]; then
        (
            cd "${BUILD_DIR}"
            run_command "${BUILD_DIR}/tests/run_tests" "${TEST_NAME}"
        )

    else
        run_command ctest --test-dir "${BUILD_DIR}/tests" --output-on-failure
    fi
}

run_feature_unit_tests()
{
    local test_name

    if [[ -z "${FEATURE_NAME}" || "${#FEATURE_UNIT_TESTS[@]}" -eq 0 ]]; then
        return
    fi

    if [[ -n "${TEST_NAME}" ]]; then
        log_line "skipping manifest feature unit tests because XQC_TEST_NAME is set"
        return
    fi

    ensure_test_certificate
    for test_name in "${FEATURE_UNIT_TESTS[@]}"; do
        (
            cd "${BUILD_DIR}"
            run_command "${BUILD_DIR}/tests/run_tests" "${test_name}"
        )
    done
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
    run_feature_unit_tests
fi

if [[ "${VALIDATION_LEVEL}" == "full" ]]; then
    run_integration_tests
fi

log_line "validation level '${VALIDATION_LEVEL}' passed"
