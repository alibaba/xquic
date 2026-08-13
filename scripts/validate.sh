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
BUILD_SSL="${XQC_BUILD_SSL:-auto}"
PREPARE_RUNTIME_FILES="${XQC_PREPARE_RUNTIME_FILES:-on}"
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
    echo "platform=$(uname -s)"
    echo "build_dir=${BUILD_DIR}"
    echo "build_type=${BUILD_TYPE}"
    echo "build_jobs=${BUILD_JOBS}"
    echo "artifact_dir=${ARTIFACT_DIR}"
    echo "ssl_type=${SSL_TYPE}"
    echo "ssl_path=${SSL_PATH}"
    echo "ssl_include=${SSL_INCLUDE}"
    echo "ssl_libs=${SSL_LIBS}"
    echo "build_ssl=${BUILD_SSL}"
    echo "prepare_runtime_files=${PREPARE_RUNTIME_FILES}"
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
        echo "ssl_include=${SSL_INCLUDE}"
        echo "ssl_libs=${SSL_LIBS}"
        echo "build_ssl=${BUILD_SSL}"
        echo "prepare_runtime_files=${PREPARE_RUNTIME_FILES}"
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
        "-DGCOV=on"
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

ssl_libs_exist()
{
    local libs=()
    local lib

    IFS=';' read -r -a libs <<< "${SSL_LIBS}"
    for lib in "${libs[@]}"; do
        [[ -f "${lib}" ]] || return 1
    done
}

ensure_ssl_backend()
{
    case "${BUILD_SSL}" in
        auto|on|off)
            ;;
        *)
            echo "XQC_BUILD_SSL must be auto, on, or off" >&2
            exit 2
            ;;
    esac

    if ssl_libs_exist; then
        return
    fi

    if [[ "${BUILD_SSL}" == "off" ]]; then
        echo "TLS libraries not found: ${SSL_LIBS}" >&2
        echo "Set XQC_SSL_PATH/XQC_SSL_LIBS or allow XQC_BUILD_SSL=auto." >&2
        exit 1
    fi

    if [[ "${SSL_TYPE}" != "boringssl" ]]; then
        echo "TLS libraries not found: ${SSL_LIBS}" >&2
        echo "Automatic TLS backend compilation is only supported for boringssl." >&2
        echo "Build ${SSL_TYPE} using README.md, then set XQC_SSL_PATH or XQC_SSL_LIBS." >&2
        exit 1
    fi

    if [[ ! -f "${SSL_PATH}/CMakeLists.txt" ]]; then
        echo "BoringSSL source not found at ${SSL_PATH}" >&2
        echo "Follow README.md to fetch BoringSSL, or set XQC_SSL_PATH." >&2
        exit 1
    fi

    run_command cmake -S "${SSL_PATH}" -B "${SSL_PATH}/build" \
        -DBUILD_SHARED_LIBS=0 \
        -DCMAKE_C_FLAGS="-fPIC" \
        -DCMAKE_CXX_FLAGS="-fPIC"
    run_command env "CMAKE_BUILD_PARALLEL_LEVEL=${BUILD_JOBS}" \
        cmake --build "${SSL_PATH}/build" --target ssl crypto
}

build_project()
{
    run_command env "CMAKE_BUILD_PARALLEL_LEVEL=${BUILD_JOBS}" \
        cmake --build "${BUILD_DIR}"
}

ensure_test_certificate()
{
    case "${PREPARE_RUNTIME_FILES}" in
        on|off)
            ;;
        *)
            echo "XQC_PREPARE_RUNTIME_FILES must be on or off" >&2
            exit 2
            ;;
    esac

    if [[ "${PREPARE_RUNTIME_FILES}" == "off" ]]; then
        return
    fi

    if [[ ! -f "${BUILD_DIR}/server.key"
        || ! -f "${BUILD_DIR}/server.crt" ]] \
        || ! openssl x509 -checkend 3600 -noout \
            -in "${BUILD_DIR}/server.crt" > /dev/null 2>&1
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
    local case_plan
    local expected
    local plan_complete
    local max_jobs
    local case_log
    local case_status=0
    local case_passed
    local case_failed

    case_log="${ARTIFACT_DIR}/case_test.log"
    case_plan="$(XQC_BUILD_DIR="${BUILD_DIR}" \
        bash "${ROOT_DIR}/scripts/case_test.sh" --execution-plan)"
    log_line "${case_plan}"

    expected="$(printf '%s\n' "${case_plan}" \
        | awk -F= '/^implemented_unique_cases=/{print $2}')"
    plan_complete="$(printf '%s\n' "${case_plan}" \
        | awk -F= '/^complete=/{print $2}')"
    max_jobs="$(printf '%s\n' "${case_plan}" \
        | awk -F= '/^max_safe_jobs=/{print $2}')"

    if [[ "${plan_complete}" != "true"
        || -z "${expected}"
        || -z "${max_jobs}" ]]
    then
        log_line "case-test plan mismatch: expected=${expected}" \
            "complete=${plan_complete} max_jobs=${max_jobs}"
        return 1
    fi

    set +e
    XQC_BUILD_DIR="${BUILD_DIR}" \
        CASE_TEST_CASE_TIMEOUT="${CASE_TEST_CASE_TIMEOUT:-300}" \
        CASE_TEST_SHARD_TIMEOUT="${CASE_TEST_SHARD_TIMEOUT:-600}" \
        bash "${ROOT_DIR}/scripts/case_test.sh" \
            --execute --parallel --jobs auto --require-complete \
        2>&1 | tee "${case_log}" | tee -a "${LOG_FILE}"
    case_status="${PIPESTATUS[0]}"
    set -e

    case_passed="$(awk '/^\[case-test:[^]]+\] .+ >>>>>>>> pass:1$/ { count++ }
        END { print count + 0 }' "${case_log}")"
    case_failed="$(awk '/^\[case-test:[^]]+\] .+ >>>>>>>> pass:0$/ { count++ }
        END { print count + 0 }' "${case_log}")"
    log_line "case-test summary: jobs=${max_jobs} passed=${case_passed}" \
        "failed=${case_failed} expected=${expected} status=${case_status}"

    if [[ "${case_status}" -ne 0
        || "${case_failed}" -ne 0
        || "${case_passed}" -ne "${expected}" ]]
    then
        return 1
    fi
}

write_environment
ensure_ssl_backend
configure_project
build_project
ensure_test_certificate

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
