#!/usr/bin/env bash

set -euo pipefail

test_case="${1:?test case is required}"
source_root="${2:?source root is required}"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/xqc-mobile-build-test.XXXXXX")"

cleanup()
{
    rm -rf -- "${fixture}"
}

trap cleanup EXIT HUP INT TERM

mkdir -p "${fixture}/cmake" "${fixture}/ssl" \
    "${fixture}/ndk/build/cmake" "${fixture}/tools"
cp "${source_root}/xqc_build.sh" "${fixture}/xqc_build.sh"
cp "${source_root}/xqc_mobile_build.sh" "${fixture}/xqc_mobile_build.sh"
printf '%s\n' "desktop-cmake-marker" > "${fixture}/CMakeLists.txt"
printf '%s\n' "mobile-cmake-marker" > "${fixture}/cmake/CMakeLists.txt"
cp "${fixture}/CMakeLists.txt" "${fixture}/CMakeLists.txt.before"
touch "${fixture}/ndk/build/cmake/android.toolchain.cmake"

cat > "${fixture}/tools/cmake" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" >> "${XQC_MOBILE_TEST_TRACE}"
mkdir -p outputs
touch outputs/libxquic.a outputs/libxquic.so
EOF

cat > "${fixture}/tools/make" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

chmod +x "${fixture}/xqc_build.sh" "${fixture}/xqc_mobile_build.sh" \
    "${fixture}/tools/cmake" "${fixture}/tools/make"

case "${test_case}" in
    happy)
        (
            cd "${fixture}"
            PATH="${fixture}/tools:${PATH}" \
                XQC_MOBILE_TEST_TRACE="${fixture}/cmake.trace" \
                ANDROID_NDK="${fixture}/ndk" \
                ./xqc_mobile_build.sh android build artifacts "${fixture}/ssl"
        )

        cmp "${fixture}/CMakeLists.txt.before" "${fixture}/CMakeLists.txt"
        [[ "$(grep -c -- '^-DXQC_MOBILE_BUILD=ON$' \
            "${fixture}/cmake.trace")" -eq 2 ]]
        test -f "${fixture}/artifacts/armeabi-v7a/libxquic.a"
        test -f "${fixture}/artifacts/armeabi-v7a/libxquic.so"
        test -f "${fixture}/artifacts/arm64-v8a/libxquic.a"
        test -f "${fixture}/artifacts/arm64-v8a/libxquic.so"
        ;;
    missing-ssl)
        set +e
        output="$(
            (
                cd "${fixture}"
                PATH="${fixture}/tools:${PATH}" \
                    XQC_MOBILE_TEST_TRACE="${fixture}/cmake.trace" \
                    ./xqc_build.sh android build artifacts \
                        "${fixture}/missing-ssl"
            ) 2>&1
        )"
        status=$?
        set -e

        [[ "${status}" -ne 0 ]]
        [[ "${output}" == *"xqc_mobile_build.sh"* ]]
        [[ "${output}" == *"ssl environment does not exist"* ]]
        cmp "${fixture}/CMakeLists.txt.before" "${fixture}/CMakeLists.txt"
        test ! -e "${fixture}/cmake.trace"
        test ! -e "${fixture}/build"
        test ! -e "${fixture}/artifacts"
        ;;
    *)
        echo "unknown test case: ${test_case}" >&2
        exit 2
        ;;
esac
