#!/bin/bash
# xqc_validate.sh -- Deterministic validation backbone for xquic
# Usage:
#   xqc_validate.sh --detect          # Detect changes, output scope
#   xqc_validate.sh --build           # Build (make -j), exit on failure
#   xqc_validate.sh --unit            # Run unit tests (./tests/run_tests)
#   xqc_validate.sh --integration     # Run full case_test.sh
#   xqc_validate.sh --all             # build + unit + full integration
#   xqc_validate.sh --quick           # build + unit only

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"

# ─── Platform detection ─────────────────────────────────────────────

detect_platform() {
    case "$(uname -s)" in
        Darwin) PLATFORM="darwin" ;;
        Linux)  PLATFORM="linux"  ;;
        *)      PLATFORM="unknown" ;;
    esac
}

setup_env() {
    detect_platform
    if [ "$PLATFORM" = "darwin" ]; then
        export EVENT_NOKQUEUE=1
    fi
}

# ─── File-to-module mapping ─────────────────────────────────────────

file_to_module() {
    case "$1" in
        src/common/utils/huffman/*)      echo "common:huffman" ;;
        src/common/utils/vint/*)         echo "common:vint" ;;
        src/common/utils/ringarray/*)    echo "common:ringarray" ;;
        src/common/utils/ringmem/*)      echo "common:ringmem" ;;
        src/common/utils/2d_hash/*)      echo "common:2dhash" ;;
        src/common/*)                    echo "common" ;;
        src/transport/xqc_conn*)         echo "transport:conn" ;;
        src/transport/xqc_engine*)       echo "transport:engine" ;;
        src/transport/xqc_stream*)       echo "transport:stream" ;;
        src/transport/xqc_packet*)       echo "transport:packet" ;;
        src/transport/xqc_frame*)        echo "transport:frame" ;;
        src/transport/xqc_send_ctl*)     echo "transport:send_ctl" ;;
        src/transport/xqc_recv_record*)  echo "transport:recv_record" ;;
        src/transport/xqc_cid*)          echo "transport:cid" ;;
        src/transport/xqc_transport_params*) echo "transport:tp" ;;
        src/transport/xqc_datagram*)     echo "transport:datagram" ;;
        src/transport/xqc_multipath*)    echo "transport:multipath" ;;
        src/transport/scheduler/*)       echo "transport:multipath" ;;
        src/transport/fec_schemes/*)     echo "transport:fec" ;;
        src/transport/*)                 echo "transport" ;;
        src/congestion_control/xqc_cubic*)    echo "cc:cubic" ;;
        src/congestion_control/xqc_new_reno*) echo "cc:reno" ;;
        src/congestion_control/xqc_bbr*)      echo "cc:bbr" ;;
        src/congestion_control/xqc_copa*)     echo "cc:copa" ;;
        src/congestion_control/*)        echo "cc" ;;
        src/tls/*)                       echo "tls" ;;
        src/http3/qpack/*)              echo "http3:qpack" ;;
        src/http3/*)                     echo "http3" ;;
        include/xquic/*)                 echo "api" ;;
        CMakeLists.txt|cmake/*)          echo "build" ;;
        tests/*)                         echo "test" ;;
        *)                               echo "other" ;;
    esac
}

# ─── Module-to-integration-scope mapping ─────────────────────────────

module_integration_scope() {
    case "$1" in
        api|build|transport:conn|transport:engine)
            echo "full" ;;
        transport:stream|transport:packet|transport:frame|transport:send_ctl)
            echo "targeted" ;;
        transport:datagram|transport:multipath)
            echo "targeted" ;;
        cc:*|cc|tls|http3)
            echo "targeted" ;;
        common|transport:recv_record|transport:cid|transport:tp)
            echo "none" ;;
        transport:fec|http3:qpack|test|other)
            echo "none" ;;
        common:*|transport)
            echo "none" ;;
        *)
            echo "none" ;;
    esac
}

# ─── Module-to-integration-hint mapping ──────────────────────────────

module_integration_hint() {
    case "$1" in
        transport:conn)      echo "connection,handshake,close" ;;
        transport:engine)    echo "connection,handshake" ;;
        transport:stream)    echo "stream,flow_control" ;;
        transport:packet)    echo "packet,illegal_packet" ;;
        transport:frame)     echo "frame,packet" ;;
        transport:send_ctl)  echo "send,loss,pacing" ;;
        transport:datagram)  echo "datagram" ;;
        transport:multipath) echo "multipath,MP,MPNS" ;;
        cc:cubic)            echo "cubic" ;;
        cc:reno)             echo "reno" ;;
        cc:bbr)              echo "BBR,BBRv2" ;;
        cc:copa)             echo "copa" ;;
        cc|cc:*)             echo "congestion" ;;
        tls)                 echo "handshake,cert,0RTT,1RTT,key_update" ;;
        http3)               echo "h3,header,GET,settings" ;;
        api)                 echo "full" ;;
        build)               echo "full" ;;
        *)                   echo "" ;;
    esac
}

# ─── Detect changes ─────────────────────────────────────────────────

cmd_detect() {
    cd "$PROJECT_ROOT"

    # Collect changed files (staged + unstaged + untracked), dedup
    local changed_files
    changed_files=$(
        {
            git diff --name-only HEAD 2>/dev/null || true
            git diff --cached --name-only 2>/dev/null || true
            git ls-files --others --exclude-standard 2>/dev/null || true
        } | sort -u
    )

    # Filter to production-relevant paths
    local prod_files=""
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        case "$f" in
            src/*|include/*|tests/*|CMakeLists.txt|cmake/*|scripts/*|demo/*|mini/*|moq/*)
                prod_files="${prod_files}${prod_files:+ }$f"
                ;;
        esac
    done <<< "$changed_files"

    if [ -z "$prod_files" ]; then
        echo "CHANGED_FILES="
        echo "BUILD_NEEDED=no"
        echo "UNIT_NEEDED=no"
        echo "AFFECTED_MODULES="
        echo "INTEGRATION_SCOPE=none"
        echo "INTEGRATION_HINT="
        return 0
    fi

    # Map files to modules, determine scope
    local modules=""
    local build_needed="no"
    local unit_needed="no"
    local max_scope="none"  # none < targeted < full
    local hints=""

    for f in $prod_files; do
        local mod
        mod=$(file_to_module "$f")
        # Dedup modules
        if ! echo "$modules" | tr ',' '\n' | grep -qx "$mod" 2>/dev/null; then
            modules="${modules}${modules:+,}$mod"
        fi

        # Build needed if any production code/header/build config
        case "$f" in
            src/*|include/*|CMakeLists.txt|cmake/*|tests/*.c|tests/*.h)
                build_needed="yes"
                ;;
        esac

        # Unit needed if production code or test code changed
        case "$f" in
            src/*|include/*|tests/unittest/*)
                unit_needed="yes"
                ;;
        esac

        # Integration scope: take the maximum
        local scope
        scope=$(module_integration_scope "$mod")
        case "$scope" in
            full)
                max_scope="full"
                ;;
            targeted)
                if [ "$max_scope" != "full" ]; then
                    max_scope="targeted"
                fi
                ;;
        esac

        # Collect hints
        local hint
        hint=$(module_integration_hint "$mod")
        if [ -n "$hint" ]; then
            hints="${hints}${hints:+,}$hint"
        fi
    done

    # Dedup hints
    hints=$(echo "$hints" | tr ',' '\n' | sort -u | tr '\n' ',' | sed 's/,$//')

    echo "CHANGED_FILES=$prod_files"
    echo "BUILD_NEEDED=$build_needed"
    echo "UNIT_NEEDED=$unit_needed"
    echo "AFFECTED_MODULES=$modules"
    echo "INTEGRATION_SCOPE=$max_scope"
    echo "INTEGRATION_HINT=$hints"
}

# ─── Prerequisite checks ────────────────────────────────────────────

check_build_dir() {
    if [ ! -d "$BUILD_DIR" ]; then
        echo "ERROR: build/ directory not found. Run cmake configuration first." >&2
        echo "See docs_ai/build/build_guide.md for setup instructions." >&2
        exit 1
    fi
    if [ ! -f "$BUILD_DIR/Makefile" ]; then
        echo "ERROR: build/Makefile not found. Run cmake configuration first." >&2
        exit 1
    fi
}

check_test_binaries() {
    if [ ! -f "$BUILD_DIR/tests/run_tests" ]; then
        echo "ERROR: tests/run_tests not found. Build with -DXQC_ENABLE_TESTING=1." >&2
        exit 1
    fi
}

check_integration_binaries() {
    if [ ! -f "$BUILD_DIR/tests/test_server" ] || [ ! -f "$BUILD_DIR/tests/test_client" ]; then
        echo "ERROR: test_server/test_client not found. Build with -DXQC_ENABLE_TESTING=1." >&2
        exit 1
    fi
}

ensure_certs() {
    cd "$BUILD_DIR"
    if [ ! -f server.key ] || [ ! -f server.crt ]; then
        echo "Generating TLS certificates..."
        openssl req -newkey rsa:2048 -x509 -nodes \
            -keyout server.key -new -out server.crt \
            -subj /CN=test.xquic.com 2>/dev/null
    fi
}

# ─── Build ───────────────────────────────────────────────────────────

cmd_build() {
    check_build_dir
    echo "=== Building xquic ==="
    cd "$BUILD_DIR"
    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
    echo "=== Build: PASS ==="
}

# ─── Unit tests ──────────────────────────────────────────────────────

cmd_unit() {
    check_build_dir
    check_test_binaries
    echo "=== Running unit tests ==="
    cd "$BUILD_DIR"
    ./tests/run_tests
    local rc=$?
    if [ $rc -eq 0 ]; then
        echo "=== Unit tests: PASS ==="
    else
        echo "=== Unit tests: FAIL (exit code $rc) ==="
        exit $rc
    fi
}

# ─── Integration tests ──────────────────────────────────────────────

cmd_integration() {
    check_build_dir
    check_integration_binaries
    setup_env
    ensure_certs
    echo "=== Running integration tests (case_test.sh) ==="
    cd "$BUILD_DIR"
    bash "$SCRIPT_DIR/case_test.sh"
    local rc=$?
    if [ $rc -eq 0 ]; then
        echo "=== Integration tests: PASS ==="
    else
        echo "=== Integration tests: FAIL (exit code $rc) ==="
        exit $rc
    fi
}

# ─── Combined modes ─────────────────────────────────────────────────

cmd_quick() {
    cmd_build
    echo ""
    cmd_unit
}

cmd_all() {
    cmd_build
    echo ""
    cmd_unit
    echo ""
    cmd_integration
}

# ─── Usage ───────────────────────────────────────────────────────────

usage() {
    cat <<'EOF'
Usage: xqc_validate.sh <command>

Commands:
  --detect         Detect changed files and output validation scope
  --build          Build xquic (make -j)
  --unit           Run unit tests (./tests/run_tests)
  --integration    Run full integration tests (case_test.sh)
  --quick          Build + unit tests
  --all            Build + unit tests + integration tests
  --help           Show this help

Output of --detect:
  CHANGED_FILES=<space-separated list>
  BUILD_NEEDED=yes|no
  UNIT_NEEDED=yes|no
  AFFECTED_MODULES=<comma-separated module list>
  INTEGRATION_SCOPE=none|targeted|full
  INTEGRATION_HINT=<comma-separated keywords>
EOF
}

# ─── Main ────────────────────────────────────────────────────────────

case "${1:-}" in
    --detect)      cmd_detect ;;
    --build)       cmd_build ;;
    --unit)        cmd_unit ;;
    --integration) cmd_integration ;;
    --quick)       cmd_quick ;;
    --all)         cmd_all ;;
    --help|-h)     usage ;;
    *)
        echo "ERROR: Unknown command '${1:-}'. Use --help for usage." >&2
        exit 1
        ;;
esac
