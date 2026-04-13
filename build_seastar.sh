#!/bin/bash
# build_seastar.sh — 使用 submodule 方式构建 xquic + seastar 集成
#
# 用法:
#   ./build_seastar.sh          # 默认构建
#   ./build_seastar.sh clean    # 清理后重新构建
#   ./build_seastar.sh deps     # 仅安装系统依赖 (Ubuntu/Debian)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build_seastar"
BORINGSSL_DIR="${SCRIPT_DIR}/third_party/boringssl"
SEASTAR_DIR="${SCRIPT_DIR}/third_party/seastar"
NPROC=$(nproc 2>/dev/null || echo 4)

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

install_deps_ubuntu() {
    info "安装 Seastar 系统依赖 (Ubuntu/Debian)..."
    sudo apt-get update
    sudo apt-get install -y \
        gcc g++ ninja-build ragel libhwloc-dev libnuma-dev \
        libpciaccess-dev libcrypto++-dev libboost-all-dev \
        libxml2-dev xfslibs-dev libgnutls28-dev liblz4-dev \
        libsctp-dev systemtap-sdt-dev libtool cmake \
        libyaml-cpp-dev libc-ares-dev stow libfmt-dev \
        diffutils valgrind doxygen libprotobuf-dev \
        protobuf-compiler libunwind-dev pkg-config \
        python3-pyelftools libevent-dev
    info "系统依赖安装完成"
}

install_deps_fedora() {
    info "安装 Seastar 系统依赖 (Fedora/RHEL)..."
    sudo dnf install -y \
        gcc gcc-c++ ninja-build ragel hwloc-devel numactl-devel \
        libpciaccess-devel cryptopp-devel boost-devel \
        libxml2-devel xfsprogs-devel gnutls-devel lz4-devel \
        lksctp-tools-devel systemtap-sdt-devel libtool cmake \
        yaml-cpp-devel c-ares-devel stow fmt-devel \
        diffutils valgrind doxygen protobuf-devel \
        protobuf-compiler libunwind-devel pkgconf \
        python3-pyelftools libevent-devel
    info "系统依赖安装完成"
}

check_submodules() {
    if [ ! -f "${SEASTAR_DIR}/CMakeLists.txt" ]; then
        info "初始化 Seastar submodule (SSH)..."
        cd "${SCRIPT_DIR}"
        git submodule update --init --recursive third_party/seastar
    fi

    if [ ! -f "${BORINGSSL_DIR}/CMakeLists.txt" ]; then
        error "BoringSSL 未找到: ${BORINGSSL_DIR}"
        error "请确保 third_party/boringssl 存在"
        exit 1
    fi
}

build_boringssl() {
    if [ -f "${BORINGSSL_DIR}/build/ssl/libssl.a" ] && [ -f "${BORINGSSL_DIR}/build/crypto/libcrypto.a" ]; then
        info "BoringSSL 已构建，跳过"
        return
    fi

    info "构建 BoringSSL..."
    mkdir -p "${BORINGSSL_DIR}/build"
    cd "${BORINGSSL_DIR}/build"
    cmake -GNinja ..
    ninja ssl crypto
    info "BoringSSL 构建完成"
}

build_xquic_seastar() {
    info "配置 xquic + Seastar 构建..."
    mkdir -p "${BUILD_DIR}"
    cd "${BUILD_DIR}"

    cmake -S "${SCRIPT_DIR}" -B "${BUILD_DIR}" \
        -DXQC_ENABLE_SEASTAR=ON \
        -DXQC_ENABLE_TESTING=ON \
        -DSSL_TYPE=boringssl \
        -DSSL_PATH="${BORINGSSL_DIR}" \
        -DSSL_INC_PATH="${BORINGSSL_DIR}/include" \
        -DSSL_LIB_PATH="${BORINGSSL_DIR}/build/ssl/libssl.a;${BORINGSSL_DIR}/build/crypto/libcrypto.a"

    info "编译 xquic_server_seastar (${NPROC} 并行)..."
    cmake --build "${BUILD_DIR}" --target xquic_server_seastar -j"${NPROC}"

    info "构建完成！可执行文件: ${BUILD_DIR}/tests/xquic_server_seastar"
}

case "${1:-build}" in
    deps)
        if command -v apt-get &>/dev/null; then
            install_deps_ubuntu
        elif command -v dnf &>/dev/null; then
            install_deps_fedora
        else
            error "不支持的包管理器，请手动安装 Seastar 依赖"
            exit 1
        fi
        ;;
    clean)
        info "清理构建目录: ${BUILD_DIR}"
        rm -rf "${BUILD_DIR}"
        check_submodules
        build_boringssl
        build_xquic_seastar
        ;;
    build|"")
        check_submodules
        build_boringssl
        build_xquic_seastar
        ;;
    *)
        echo "用法: $0 [build|clean|deps]"
        exit 1
        ;;
esac
