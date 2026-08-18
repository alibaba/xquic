#!/usr/bin/env bash
# Copyright (c) 2022, Alibaba Group Holding Limited

set -euo pipefail

ANDROID_ARCHS=(armeabi-v7a arm64-v8a)
IOS_ARCHS=(armv7 arm64 x86_64)
HARMONY_ARCHS=(arm64-v8a)
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CMAKE_CMD="cmake"

usage()
{
    echo "usage: $0 <ios|android|harmony> <build_dir> <artifact_dir> [ssl_path]" >&2
}

fail()
{
    echo "$1" >&2
    exit "${2:-1}"
}

prepare_output_dir()
{
    local name="$1"
    local path="$2"

    if [[ -z "${path}" ]]; then
        fail "${name} MUST NOT be empty" 2
    fi

    rm -rf -- "${path}"
    mkdir -p -- "${path}"
    echo "created ${name} directory (${path})"
}

if [[ "$#" -lt 3 || "$#" -gt 4 ]]; then
    usage
    exit 2
fi

platform="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
build_arg="$2"
artifact_arg="$3"
ssl_type="boringssl"
ssl_path="${4:-${ROOT_DIR}/third_party/boringssl}"

validate_output_arg()
{
    local name="$1"
    local value="$2"

    case "${value}" in
        ""|/*|.|..|../*|*/..|*/../*)
            fail "${name} must be a non-empty relative path without '..'" 2
            ;;
    esac
}

validate_output_arg "build_dir" "${build_arg}"
validate_output_arg "artifact_dir" "${artifact_arg}"
build_dir="${ROOT_DIR}/${build_arg}"
artifact_dir="${ROOT_DIR}/${artifact_arg}"

if [[ ! -d "${ssl_path}" ]]; then
    fail "ssl environment does not exist: ${ssl_path}"
fi

configures=(
    "-DXQC_MOBILE_BUILD=ON"
    "-DSSL_TYPE=${ssl_type}"
    "-DSSL_PATH=${ssl_path}"
    "-DXQC_ENABLE_TESTING=OFF"
    "-DXQC_BUILD_SAMPLE=OFF"
    "-DGCOV=OFF"
    "-DXQC_ENABLE_RENO=OFF"
    "-DXQC_ENABLE_BBR2=ON"
    "-DXQC_ENABLE_COPA=OFF"
    "-DXQC_ENABLE_UNLIMITED=OFF"
    "-DXQC_ENABLE_MP_INTEROP=OFF"
    "-DXQC_DISABLE_LOG=OFF"
    "-DXQC_ONLY_ERROR_LOG=ON"
    "-DXQC_COMPAT_GENERATE_SR_PKT=ON"
)

case "${platform}" in
    ios)
        if [[ -z "${IOS_CMAKE_TOOLCHAIN:-}" ]]; then
            fail "IOS_CMAKE_TOOLCHAIN MUST be defined"
        fi
        if [[ ! -f "${IOS_CMAKE_TOOLCHAIN}" ]]; then
            fail "iOS CMake toolchain does not exist: ${IOS_CMAKE_TOOLCHAIN}"
        fi

        archs=("${IOS_ARCHS[@]}")
        configures+=(
            "-DBORINGSSL_PREFIX=bs"
            "-DBORINGSSL_PREFIX_SYMBOLS=${ROOT_DIR}/bssl_symbols.txt"
            "-DDEPLOYMENT_TARGET=10.0"
            "-DCMAKE_BUILD_TYPE=Minsizerel"
            "-DCMAKE_TOOLCHAIN_FILE=${IOS_CMAKE_TOOLCHAIN}"
            "-DENABLE_BITCODE=OFF"
            "-DXQC_NO_SHARED=ON"
            "-DXQC_ENABLE_TH3=ON"
        )
        ;;
    android)
        if [[ -z "${ANDROID_NDK:-}" ]]; then
            fail "ANDROID_NDK MUST be defined"
        fi

        android_toolchain="${ANDROID_NDK}/build/cmake/android.toolchain.cmake"
        if [[ ! -f "${android_toolchain}" ]]; then
            fail "Android CMake toolchain does not exist: ${android_toolchain}"
        fi

        archs=("${ANDROID_ARCHS[@]}")
        configures+=(
            "-DCMAKE_BUILD_TYPE=Minsizerel"
            "-DCMAKE_TOOLCHAIN_FILE=${android_toolchain}"
            "-DANDROID_STL=c++_shared"
            "-DANDROID_NATIVE_API_LEVEL=android-19"
            "-DXQC_ENABLE_TH3=ON"
        )
        ;;
    harmony)
        if [[ -z "${HMOS_CMAKE_TOOLCHAIN:-}" ]]; then
            fail "HMOS_CMAKE_TOOLCHAIN MUST be defined"
        fi
        if [[ ! -f "${HMOS_CMAKE_TOOLCHAIN}" ]]; then
            fail "HarmonyOS CMake toolchain does not exist: ${HMOS_CMAKE_TOOLCHAIN}"
        fi
        if [[ -z "${HMOS_CMAKE_PATH:-}" ]]; then
            fail "HMOS_CMAKE_PATH MUST be defined"
        fi
        if [[ ! -x "${HMOS_CMAKE_PATH}" ]]; then
            fail "HarmonyOS CMake command is not executable: ${HMOS_CMAKE_PATH}"
        fi

        CMAKE_CMD="${HMOS_CMAKE_PATH}"
        archs=("${HARMONY_ARCHS[@]}")
        configures+=(
            "-DCMAKE_BUILD_TYPE=Release"
            "-DCMAKE_TOOLCHAIN_FILE=${HMOS_CMAKE_TOOLCHAIN}"
            "-DDISABLE_WARNINGS=ON"
        )
        ;;
    *)
        usage
        fail "unsupported platform: ${platform}" 2
        ;;
esac

platform_configure_args()
{
    local arch="$1"

    PLATFORM_ARGS=()
    case "${platform}" in
        ios)
            PLATFORM_ARGS+=("-DARCHS=${arch}")
            if [[ "${arch}" == "x86_64" ]]; then
                PLATFORM_ARGS+=("-DPLATFORM=SIMULATOR64")
            elif [[ "${arch}" == "i386" ]]; then
                PLATFORM_ARGS+=("-DPLATFORM=SIMULATOR")
            fi
            ;;
        harmony)
            PLATFORM_ARGS+=("-DOHOS_ARCH=${arch}")
            ;;
        android)
            PLATFORM_ARGS+=("-DANDROID_ABI=${arch}")
            ;;
    esac
}

prepare_output_dir "build" "${build_dir}"
prepare_output_dir "artifact" "${artifact_dir}"

for arch in "${archs[@]}"; do
    platform_configure_args "${arch}"

    rm -rf -- "${build_dir}/CMakeCache.txt" \
        "${build_dir}/CMakeFiles" \
        "${build_dir}/Makefile" \
        "${build_dir}/cmake_install.cmake" \
        "${build_dir}/include" \
        "${build_dir}/outputs" \
        "${build_dir}/third_party"

    echo "compiling xquic for ${arch}"
    (
        cd "${build_dir}"
        "${CMAKE_CMD}" "${configures[@]}" "${PLATFORM_ARGS[@]}" \
            "-DLIBRARY_OUTPUT_PATH=${build_dir}/outputs/" "${ROOT_DIR}"
        make -j 4
    )

    mkdir -p -- "${artifact_dir}/${arch}"
    shopt -s nullglob
    libraries=("${build_dir}"/outputs/*.a "${build_dir}"/outputs/*.so)
    shopt -u nullglob
    if [[ "${#libraries[@]}" -eq 0 ]]; then
        fail "no libraries were produced for ${arch}"
    fi
    cp -f -- "${libraries[@]}" "${artifact_dir}/${arch}/"
done

make_fat()
{
    local library="$1"
    local lipo_args=(lipo -create)
    local arch

    for arch in "${archs[@]}"; do
        lipo_args+=("-arch" "${arch}" "${artifact_dir}/${arch}/${library}")
    done
    lipo_args+=("-output" "${ROOT_DIR}/ios/xquic/xquic/Libs/${library}")
    "${lipo_args[@]}"
}

if [[ "${platform}" == "ios" ]]; then
    mkdir -p -- "${ROOT_DIR}/ios/xquic/xquic/Headers" \
        "${ROOT_DIR}/ios/xquic/xquic/Libs"
    make_fat libxquic.a
    make_fat libcrypto.a
    make_fat libssl.a
    cp -f -- "${ROOT_DIR}"/include/xquic/* \
        "${ROOT_DIR}/ios/xquic/xquic/Headers/"
    cp -f -- "${build_dir}"/include/xquic/* \
        "${ROOT_DIR}/ios/xquic/xquic/Headers/"
fi
