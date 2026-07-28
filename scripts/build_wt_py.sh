#!/usr/bin/env bash
# Build libxquic_wt_py shared library for pyxquic-wt Python package.
#
# Usage:
#   ./scripts/build_wt_py.sh              # build with babassl (default)
#   SSL_BACKEND=boringssl ./scripts/build_wt_py.sh   # build with boringssl
#   ./scripts/build_wt_py.sh --install    # same + pip install -e .
#
# Output: xquic_webtransport/python/pyxquic_wt/libxquic_wt_py.{so,dylib}
#
# Prerequisites: C compiler (cc), cmake, make

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ROOT/build_wt"
PKG_DIR="$ROOT/xquic_webtransport/python/pyxquic_wt"
SSL_BACKEND="${SSL_BACKEND:-babassl}"

WT_SOURCES=(
    src/webtransport/xqc_webtransport_ctx.c
    src/webtransport/xqc_webtransport_conn.c
    src/webtransport/xqc_webtransport_request.c
    src/webtransport/xqc_webtransport_defs.c
    src/webtransport/xqc_webtransport_dgram.c
    src/webtransport/xqc_webtransport_session.c
    src/webtransport/xqc_webtransport_stream.c
    src/webtransport/xqc_webtransport_wire.c
    src/webtransport/xqc_wt_py_api.c
)

echo "==> Building libxquic_wt_py"
echo "    Root:     $ROOT"
echo "    Build:    $BUILD_DIR"
echo "    Output:   $PKG_DIR"
echo "    SSL:      $SSL_BACKEND"

NCPU="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

# --- Step 1: Build SSL backend ---
if [ "$SSL_BACKEND" = "boringssl" ]; then
    SSL_DIR="$ROOT/third_party/boringssl"
    BSSL_BUILD="$SSL_DIR/build"
    if [ ! -f "$BSSL_BUILD/libssl.a" ]; then
        echo "==> Building BoringSSL..."
        if [ ! -f "$SSL_DIR/CMakeLists.txt" ]; then
            echo "ERROR: BoringSSL source not found at $SSL_DIR"
            echo "Run: git submodule update --init --recursive"
            exit 1
        fi
        mkdir -p "$BSSL_BUILD"
        cd "$BSSL_BUILD"
        cmake "$SSL_DIR" -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON 2>/dev/null
        make ssl crypto -j"$NCPU" 2>/dev/null
        echo "    BoringSSL built"
    fi
    SSL_LIB_A="$BSSL_BUILD/libssl.a"
    CRYPTO_LIB_A="$BSSL_BUILD/libcrypto.a"
    SSL_INC="$SSL_DIR/include"
    CMAKE_SSL_ARGS="-DSSL_TYPE=boringssl -DSSL_PATH=$SSL_DIR"
else
    SSL_DIR="$ROOT/third_party/babassl"
    if [ ! -f "$SSL_DIR/libssl.a" ]; then
        echo "==> Building BabaSSL..."
        if [ ! -f "$SSL_DIR/Configure" ]; then
            echo "ERROR: BabaSSL source not found at $SSL_DIR"
            echo "Run: git submodule update --init --recursive"
            exit 1
        fi
        cd "$SSL_DIR"
        ./config --prefix="$SSL_DIR/output" no-shared 2>/dev/null
        make -j"$NCPU" 2>/dev/null
        echo "    BabaSSL built"
    fi
    SSL_LIB_A="$SSL_DIR/libssl.a"
    CRYPTO_LIB_A="$SSL_DIR/libcrypto.a"
    SSL_INC="$SSL_DIR/include"
    CMAKE_SSL_ARGS="-DSSL_TYPE=babassl -DSSL_PATH=$SSL_DIR"
fi

# --- Step 2: Build libxquic-static.a via cmake ---
if [ ! -f "$BUILD_DIR/libxquic-static.a" ]; then
    echo "==> Building libxquic-static.a..."
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    cmake "$ROOT" \
        -DCMAKE_BUILD_TYPE=Release \
        -DXQC_ENABLE_TESTING=OFF \
        -DXQC_NO_PID_FILE=1 \
        $CMAKE_SSL_ARGS \
        2>/dev/null
    make xquic-static -j"$NCPU" 2>/dev/null
    echo "    libxquic-static.a built"
fi

# --- Step 3: Compile shared library ---
echo "==> Compiling libxquic_wt_py..."
cd "$ROOT"

# Determine output name
case "$(uname -s)" in
    Darwin*) LIB_NAME="libxquic_wt_py.dylib" ;;
    *)       LIB_NAME="libxquic_wt_py.so" ;;
esac

# Extra defines for boringssl
EXTRA_CFLAGS=""
if [ "$SSL_BACKEND" = "boringssl" ]; then
    EXTRA_CFLAGS="-DNOCRYPT=1"
fi

# Platform-specific link flags
LINK_FLAGS=()
case "$(uname -s)" in
    Darwin*)
        LINK_FLAGS+=(
            -Wl,-force_load,"$BUILD_DIR/libxquic-static.a"
            -Wl,-force_load,"$SSL_LIB_A"
            -Wl,-force_load,"$CRYPTO_LIB_A"
            -framework Security -framework CoreFoundation
        )
        # BoringSSL is C++ — need libc++
        if [ "$SSL_BACKEND" = "boringssl" ]; then
            LINK_FLAGS+=(-lc++)
        fi
        ;;
    *)
        LINK_FLAGS+=(
            -Wl,--whole-archive
            "$BUILD_DIR/libxquic-static.a"
            "$SSL_LIB_A"
            "$CRYPTO_LIB_A"
            -Wl,--no-whole-archive
            -lpthread -ldl -lm
        )
        # BoringSSL is C++ — need libstdc++
        if [ "$SSL_BACKEND" = "boringssl" ]; then
            LINK_FLAGS+=(-lstdc++)
        fi
        ;;
esac

cc -shared -o "$BUILD_DIR/$LIB_NAME" \
    -I"$ROOT" -I"$ROOT/include" -I"$SSL_INC" \
    $EXTRA_CFLAGS \
    "${WT_SOURCES[@]}" \
    "${LINK_FLAGS[@]}" \
    -fPIC -w

echo "    Built: $BUILD_DIR/$LIB_NAME"

# --- Step 4: Copy to package directory ---
mkdir -p "$PKG_DIR"
cp "$BUILD_DIR/$LIB_NAME" "$PKG_DIR/$LIB_NAME"
echo "    Copied to: $PKG_DIR/$LIB_NAME"

# Verify no dynamic SSL dependency
echo "==> Verifying no external SSL dependency..."
case "$(uname -s)" in
    Darwin*)
        if otool -L "$PKG_DIR/$LIB_NAME" | grep -q "libssl\|libcrypto"; then
            echo "    WARNING: still depends on dynamic SSL"
        else
            echo "    OK: no external SSL dependency"
        fi
        ;;
    *)
        if ldd "$PKG_DIR/$LIB_NAME" 2>/dev/null | grep -q "libssl\|libcrypto"; then
            echo "    WARNING: still depends on dynamic SSL"
        else
            echo "    OK: no external SSL dependency"
        fi
        ;;
esac

# --- Optional: pip install ---
if [ "${1:-}" = "--install" ]; then
    echo "==> Installing pyxquic-wt..."
    cd "$ROOT/xquic_webtransport/python"
    pip install -e . 2>/dev/null
    echo "    Installed!"
fi

echo "==> Done! Library: $PKG_DIR/$LIB_NAME"
echo ""
echo "To use without pip install:"
echo "  export XQUIC_LIB_PATH=$PKG_DIR"
echo "  python -c 'from pyxquic_wt import serve; print(\"OK\")'"
