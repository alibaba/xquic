#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_SCENARIOS="bidi datagram large-datagram-reject pre-session-datagram pre-session-stream-overflow close-gates peer-close-fin reset-prefix server-bidi multi-session split-header fc-disabled-single-session fc-data-blocked fc-stream-blocked compat-legacy strict-reject-legacy client-reject-missing-wt-enabled client-reject-missing-h3-datagram client-reject-missing-connect client-reject-missing-dgram-tp client-reject-missing-reset-at strict-missing-wt-enabled strict-missing-h3-datagram strict-missing-connect strict-missing-dgram-tp strict-missing-reset-at invalid-datagram churn"
ASAN="0"
SANITIZERS="address,undefined"
CLIENT_RUNS="4"
KEEP_LOGS="0"
SKIP_BUILD="0"
SSL_BACKEND="babassl"
SCENARIOS="$DEFAULT_SCENARIOS"

usage() {
    cat <<EOF
Usage: $0 [options]

Options:
  --scenarios "LIST"       Space-separated scenario list
  --runs N                 Number of churn sessions (default: 4)
  --keep-logs              Keep temporary logs after exit
  --skip-build             Reuse existing binaries
  --asan                   Build and run with address,undefined sanitizers
  --sanitizers LIST        Sanitizer list used with --asan (default: address,undefined)
  --ssl BACKEND            babassl or boringssl (default: babassl)
  -h, --help               Show this help
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --scenarios)
            SCENARIOS="$2"
            shift 2
            ;;
        --runs)
            CLIENT_RUNS="$2"
            shift 2
            ;;
        --keep-logs)
            KEEP_LOGS="1"
            shift
            ;;
        --skip-build)
            SKIP_BUILD="1"
            shift
            ;;
        --asan)
            ASAN="1"
            shift
            ;;
        --sanitizers)
            SANITIZERS="$2"
            shift 2
            ;;
        --ssl)
            SSL_BACKEND="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'unknown option: %s\n' "$1"
            usage
            exit 1
            ;;
    esac
done

DEFAULT_BUILD_DIR="$ROOT_DIR/build_wt_e2e"
if [ "$ASAN" = "1" ]; then
    DEFAULT_BUILD_DIR="$ROOT_DIR/build_wt_e2e_asan"
fi
BUILD_DIR="$DEFAULT_BUILD_DIR"
BIN_DIR="$BUILD_DIR/src/webtransport"
SERVER_BIN="$BIN_DIR/wt_test_server"
CLIENT_BIN="$BIN_DIR/wt_test_client"
CERT_FILE="$ROOT_DIR/certs/localhost.crt"
KEY_FILE="$ROOT_DIR/certs/localhost.key"
HOST="127.0.0.1"
PORT=""

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/xquic-wt-e2e.XXXXXX")"
SERVER_PID=""

log() {
    printf '%s\n' "$*"
}

dump_logs() {
    log "---- server.log ----"
    if [ -f "$TMP_DIR/server.log" ]; then
        sed -n '1,240p' "$TMP_DIR/server.log"
    else
        log "(missing)"
    fi

    for file in "$TMP_DIR"/client-*.log; do
        [ -e "$file" ] || continue
        log "---- $(basename "$file") ----"
        sed -n '1,200p' "$file"
    done
}

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi

    if [ "$KEEP_LOGS" = "1" ]; then
        log "logs kept at $TMP_DIR"
    else
        rm -rf "$TMP_DIR"
    fi
}

trap cleanup EXIT

port_in_use() {
    local port="$1"
    if command -v lsof >/dev/null 2>&1; then
        lsof -nP -iUDP:"$port" >/dev/null 2>&1
    else
        return 1
    fi
}

pick_port() {
    if [ -n "$PORT" ]; then
        if port_in_use "$PORT"; then
            log "port $PORT is already in use"
            return 1
        fi
        return 0
    fi

    local candidate
    for candidate in $(seq 18443 18493); do
        if ! port_in_use "$candidate"; then
            PORT="$candidate"
            return 0
        fi
    done

    log "no free UDP port found in 18443..18493"
    return 1
}

ensure_binaries() {
    check_no_direct_wt_quic_datagram

    if [ "$SKIP_BUILD" = "1" ] && [ -x "$SERVER_BIN" ] && [ -x "$CLIENT_BIN" ]; then
        return 0
    fi

    local ssl_dir ssl_lib_a crypto_lib_a ssl_inc cmake_ssl_args
    case "$SSL_BACKEND" in
        babassl)
            ssl_dir="$ROOT_DIR/third_party/babassl"
            ssl_lib_a="$ssl_dir/libssl.a"
            crypto_lib_a="$ssl_dir/libcrypto.a"
            ssl_inc="$ssl_dir/include"
            cmake_ssl_args=(-DSSL_TYPE=babassl -DSSL_PATH="$ssl_dir")
            ;;
        boringssl)
            ssl_dir="$ROOT_DIR/third_party/boringssl"
            ssl_lib_a="$ssl_dir/build/libssl.a"
            crypto_lib_a="$ssl_dir/build/libcrypto.a"
            ssl_inc="$ssl_dir/include"
            cmake_ssl_args=(-DSSL_TYPE=boringssl -DSSL_PATH="$ssl_dir")
            ;;
        *)
            log "unsupported SSL_BACKEND: $SSL_BACKEND"
            return 1
            ;;
    esac

    require_file "$ssl_lib_a" "SSL library"
    require_file "$crypto_lib_a" "crypto library"

    mkdir -p "$BUILD_DIR" "$BIN_DIR"

    if [ "$SKIP_BUILD" != "1" ]; then
        log "[ BUILD    ] xquic-static"
        if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
            local cmake_build_type cmake_extra_args
            cmake_build_type=Release
            cmake_extra_args=()
            if [ "$ASAN" = "1" ]; then
                cmake_build_type=Debug
                cmake_extra_args=(
                    -DCMAKE_C_FLAGS="-O1 -g -fsanitize=$SANITIZERS -fno-omit-frame-pointer"
                    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=$SANITIZERS"
                    -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=$SANITIZERS"
                )
            fi
            if [ "$ASAN" = "1" ]; then
                cmake -S "$ROOT_DIR" -B "$BUILD_DIR" \
                    -DCMAKE_BUILD_TYPE="$cmake_build_type" \
                    -DXQC_ENABLE_TESTING=OFF \
                    -DXQC_NO_PID_FILE=1 \
                    "${cmake_ssl_args[@]}" \
                    "${cmake_extra_args[@]}"
            else
                cmake -S "$ROOT_DIR" -B "$BUILD_DIR" \
                    -DCMAKE_BUILD_TYPE="$cmake_build_type" \
                    -DXQC_ENABLE_TESTING=OFF \
                    -DXQC_NO_PID_FILE=1 \
                    "${cmake_ssl_args[@]}"
            fi
        fi
        cmake --build "$BUILD_DIR" --target xquic-static -j4

        local event_cflags_raw event_libs_raw
        event_cflags_raw=""
        event_libs_raw="-levent"
        if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libevent; then
            event_cflags_raw="$(pkg-config --cflags libevent)"
            event_libs_raw="$(pkg-config --libs libevent)"
        fi

        local wt_sources link_libs common_cflags
        wt_sources=(
            "$ROOT_DIR/src/webtransport/xqc_webtransport_ctx.c"
            "$ROOT_DIR/src/webtransport/xqc_webtransport_conn.c"
            "$ROOT_DIR/src/webtransport/xqc_webtransport_request.c"
            "$ROOT_DIR/src/webtransport/xqc_webtransport_defs.c"
            "$ROOT_DIR/src/webtransport/xqc_webtransport_dgram.c"
            "$ROOT_DIR/src/webtransport/xqc_webtransport_session.c"
            "$ROOT_DIR/src/webtransport/xqc_webtransport_stream.c"
            "$ROOT_DIR/src/webtransport/xqc_webtransport_wire.c"
        )
        common_cflags=(-std=gnu11 -O2 -I"$ROOT_DIR" -I"$ROOT_DIR/include" -I"$ssl_inc")
        if [ "$ASAN" = "1" ]; then
            common_cflags=(-std=gnu11 -O1 -g -fsanitize="$SANITIZERS" -fno-omit-frame-pointer -I"$ROOT_DIR" -I"$ROOT_DIR/include" -I"$ssl_inc")
        fi
        if [ -n "$event_cflags_raw" ]; then
            local flag
            for flag in $event_cflags_raw; do
                common_cflags+=("$flag")
            done
        fi
        link_libs=("$BUILD_DIR/libxquic-static.a" "$ssl_lib_a" "$crypto_lib_a")
        local lib
        for lib in $event_libs_raw; do
            link_libs+=("$lib")
        done
        link_libs+=(-lm -ldl -lstdc++ -lpthread)
        if [ "$ASAN" = "1" ]; then
            link_libs=(-fsanitize="$SANITIZERS" "${link_libs[@]}")
        fi

        case "$(uname -s)" in
            Darwin*)
                link_libs+=(-framework Security -framework CoreFoundation)
                ;;
        esac

        log "[ BUILD    ] wt_test_server"
        cc "${common_cflags[@]}" -o "$SERVER_BIN" \
            "${wt_sources[@]}" "$ROOT_DIR/src/webtransport/wt_demo_server.c" \
            "${link_libs[@]}"

        log "[ BUILD    ] wt_test_client"
        cc "${common_cflags[@]}" -o "$CLIENT_BIN" \
            "${wt_sources[@]}" "$ROOT_DIR/src/webtransport/wt_test_client.c" \
            "${link_libs[@]}"
    fi

    if [ ! -x "$SERVER_BIN" ]; then
        log "missing server binary: $SERVER_BIN"
        return 1
    fi
    if [ ! -x "$CLIENT_BIN" ]; then
        log "missing client binary: $CLIENT_BIN"
        return 1
    fi
}

require_file() {
    local path="$1"
    local name="$2"
    if [ ! -f "$path" ]; then
        log "missing $name: $path"
        return 1
    fi
}

check_no_direct_wt_quic_datagram() {
    local direct_read_handler
    direct_read_handler="xqc_wt_""dgram_read_handler"
    if grep -R "$direct_read_handler" "$ROOT_DIR/src" "$ROOT_DIR/include" "$ROOT_DIR/tests" >/dev/null 2>&1; then
        log "WT draft-15 datagrams must enter through H3 Datagram, not a direct QUIC datagram handler"
        return 1
    fi
    local raw_dgram_api
    raw_dgram_api="xqc_""datagram_send"
    if grep "$raw_dgram_api" "$ROOT_DIR/src/webtransport/wt_test_client.c" >/dev/null 2>&1; then
        log "WT draft-15 e2e client must send test datagrams through H3 Datagram APIs"
        return 1
    fi
    if grep "while (dgram_blk->data_sent" "$ROOT_DIR/src/webtransport/xqc_webtransport_dgram.c" >/dev/null 2>&1; then
        log "WT draft-15 datagrams preserve message boundaries; sender must not fragment one WT datagram into multiple H3 datagrams"
        return 1
    fi
    if grep "|| !peer->wt_initial_max_.*_present" "$ROOT_DIR/src/webtransport/xqc_webtransport_ctx.c" >/dev/null 2>&1; then
        log "draft-15 strict requirements must not treat WT flow-control SETTINGS as mandatory"
        return 1
    fi
    if grep "reserve_stream && session->drain_received" "$ROOT_DIR/src/webtransport/xqc_webtransport_session.c" >/dev/null 2>&1; then
        log "WT_DRAIN_SESSION must not block opening new WebTransport streams"
        return 1
    fi
    if ! grep "XQC_WT_CAPSULE_MAX_STREAM_DATA" "$ROOT_DIR/src/webtransport/xqc_webtransport_ctx.c" >/dev/null 2>&1; then
        log "prohibited WT_MAX_STREAM_DATA capsule must be handled as a session error"
        return 1
    fi
    if ! grep "H3_DATAGRAM_ERROR" "$ROOT_DIR/src/webtransport/xqc_webtransport_session.c" >/dev/null 2>&1; then
        log "oversized WT_MAX_STREAMS must close with H3_DATAGRAM_ERROR"
        return 1
    fi
    if ! grep "XQC_WT_ERROR_BUFFERED_STREAM_REJECTED" "$ROOT_DIR/src/webtransport/xqc_webtransport_ctx.c" >/dev/null 2>&1; then
        log "buffered WT stream overflow must reject the stream with WT_BUFFERED_STREAM_REJECTED"
        return 1
    fi
    if grep -A6 "xqc_h3_conn_set_user_data" "$ROOT_DIR/src/http3/xqc_h3_conn.c" | grep "xqc_conn_set_transport_user_data" >/dev/null 2>&1; then
        log "H3 user_data setter must not overwrite transport user_data"
        return 1
    fi
    if grep "xqc_conn_set_transport_user_data(conn, wt_conn)" "$ROOT_DIR/src/webtransport/xqc_webtransport_ctx.c" >/dev/null 2>&1; then
        log "WT core must not overwrite transport user_data"
        return 1
    fi
    if grep -A80 "xqc_wt_ctx_init_for_alpns" "$ROOT_DIR/src/webtransport/xqc_webtransport_ctx.c" | grep "xqc_h3_ctx_init(engine" >/dev/null 2>&1; then
        log "WT scoped ALPN init must not register callbacks for every H3 ALPN"
        return 1
    fi
    if grep "&processed" "$ROOT_DIR/src/webtransport/xqc_webtransport_ctx.c" >/dev/null 2>&1; then
        log "WT stream read callbacks must not overload user_data as a processed-byte output parameter"
        return 1
    fi
    if grep "webtransport_session_handshake_finished_notify" "$ROOT_DIR/include/xquic/xqc_webtransport.h" "$ROOT_DIR/src/webtransport/xqc_webtransport_ctx.c" "$ROOT_DIR/src/webtransport/wt_test_client.c" >/dev/null 2>&1; then
        log "WT handshake-finished callback is connection-scoped, not session-scoped"
        return 1
    fi
    if grep "wt_.*stream_write_notify" "$ROOT_DIR/include/xquic/xqc_webtransport.h" >/dev/null 2>&1; then
        log "WT C SDK must not expose stream write callbacks until both uni and bidi write readiness are bridged"
        return 1
    fi
    if ! grep "dgram_acked_notify .*wt_h3_dgram_acked_notify" "$ROOT_DIR/src/webtransport/xqc_webtransport_ctx.c" >/dev/null 2>&1; then
        log "WT datagram ack callback must be bridged from H3 datagram callbacks"
        return 1
    fi
    if ! grep "dgram_lost_notify .*wt_h3_dgram_lost_notify" "$ROOT_DIR/src/webtransport/xqc_webtransport_ctx.c" >/dev/null 2>&1; then
        log "WT datagram lost callback must be bridged from H3 datagram callbacks"
        return 1
    fi
}

start_server() {
    local mode="${1:-draft15}"
    local max_data="${2:-16777216}"
    local max_bidi="${3:-1024}"
    local max_uni="${4:-1024}"
    local extra="${5:-}"

    log "[ RUN      ] webtransport_draft15.server_start"
    (
        cd "$ROOT_DIR"
        if [ -n "$extra" ]; then
            exec env ASAN_OPTIONS="detect_leaks=0:abort_on_error=1" \
                UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1}" \
                "$SERVER_BIN" -p "$PORT" -c "$CERT_FILE" -k "$KEY_FILE" -l e \
                -m "$mode" -d "$max_data" -b "$max_bidi" -u "$max_uni" $extra
        else
            exec env ASAN_OPTIONS="detect_leaks=0:abort_on_error=1" \
                UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1}" \
                "$SERVER_BIN" -p "$PORT" -c "$CERT_FILE" -k "$KEY_FILE" -l e \
                -m "$mode" -d "$max_data" -b "$max_bidi" -u "$max_uni"
        fi
    ) >"$TMP_DIR/server.log" 2>&1 &
    SERVER_PID="$!"

    local i
    for i in $(seq 1 50); do
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            log "[  FAILED  ] webtransport_draft15.server_start"
            dump_logs
            return 1
        fi
        if port_in_use "$PORT"; then
            log "[       OK ] webtransport_draft15.server_start"
            return 0
        fi
        sleep 0.1
    done

    if kill -0 "$SERVER_PID" 2>/dev/null; then
        log "[       OK ] webtransport_draft15.server_start"
        return 0
    fi

    log "[  FAILED  ] webtransport_draft15.server_start"
    dump_logs
    return 1
}

run_client_once() {
    local index="$1"
    local scenario="${2:-bidi}"
    local mode="${3:-draft15}"
    local expect="${4:-pass}"
    local extra="${5:-}"
    local log_file="$TMP_DIR/client-$index.log"

    set +e
    env ASAN_OPTIONS="detect_leaks=0:abort_on_error=1" \
        UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1}" \
        "$CLIENT_BIN" "$HOST" "$PORT" --scenario "$scenario" --mode "$mode" $extra >"$log_file" 2>&1
    local rc=$?
    set -e

    if [ "$expect" = "fail" ]; then
        if [ "$rc" -eq 0 ]; then
            log "[  FAILED  ] webtransport_draft15.$scenario#$index expected failure"
            dump_logs
            return 1
        fi
    else
        if [ "$rc" -ne 0 ]; then
            log "[  FAILED  ] webtransport_draft15.$scenario#$index"
            dump_logs
            return 1
        fi
    fi

    if ! grep -q "WebTransport client interop: PASS" "$log_file"; then
        log "[  FAILED  ] webtransport_draft15.$scenario#$index"
        dump_logs
        return 1
    fi

    case "$scenario" in
        bidi|churn)
            grep -q "\\[OK\\] bidi-echo" "$log_file" \
                && grep -q "\\[OK\\] bidi-fin" "$log_file" ;;
        datagram)
            grep -q "\\[OK\\] datagram-echo" "$log_file" ;;
        large-datagram-reject)
            grep -q "\\[OK\\] large-datagram-reject" "$log_file" ;;
        pre-session-datagram)
            grep -q "\\[OK\\] pre-session-datagram" "$log_file" ;;
        pre-session-stream-overflow)
            grep -q "\\[OK\\] pre-session-stream-overflow" "$log_file" \
                && grep -q "\\[OK\\] bidi-echo" "$log_file" ;;
        close-gates)
            grep -q "\\[OK\\] close-gates" "$log_file" ;;
        peer-close-fin)
            grep -q "\\[OK\\] peer-close-fin" "$log_file" ;;
        reset-prefix)
            grep -q "\\[OK\\] reset-prefix" "$log_file" ;;
        server-bidi)
            grep -q "\\[OK\\] server-bidi" "$log_file" ;;
        multi-session)
            grep -q "\\[OK\\] multi-session" "$log_file" ;;
        split-header)
            grep -q "\\[OK\\] split-header" "$log_file" ;;
        fc-data-blocked)
            grep -q "\\[OK\\] fc-data-blocked" "$log_file" ;;
        fc-stream-blocked)
            grep -q "\\[OK\\] fc-stream-blocked" "$log_file" ;;
        fc-disabled-single-session)
            grep -q "\\[OK\\] fc-disabled-single-session" "$log_file" ;;
        compat-legacy)
            grep -q "\\[OK\\] compat-legacy" "$log_file" ;;
        strict-reject-legacy)
            grep -q "\\[OK\\] strict-reject-legacy" "$log_file" \
                && ! grep -q "\\[INFO\\] Extended CONNECT sent" "$log_file" ;;
        client-reject-*)
            grep -q "\\[OK\\] client-reject-requirements" "$log_file" \
                && ! grep -q "\\[INFO\\] Extended CONNECT sent" "$log_file" ;;
        strict-missing-wt-enabled)
            grep -q "\\[OK\\] strict-missing-wt-enabled" "$log_file" ;;
        strict-missing-h3-datagram)
            grep -q "\\[OK\\] strict-missing-h3-datagram" "$log_file" ;;
        strict-missing-connect)
            grep -q "\\[OK\\] strict-missing-connect" "$log_file" ;;
        strict-missing-dgram-tp)
            grep -q "\\[OK\\] strict-missing-dgram-tp" "$log_file" ;;
        strict-missing-reset-at)
            grep -q "\\[OK\\] strict-missing-reset-at" "$log_file" ;;
        invalid-datagram)
            grep -q "\\[OK\\] invalid-datagram" "$log_file" ;;
        *)
            false ;;
    esac || {
        log "[  FAILED  ] webtransport_draft15.$scenario#$index"
        dump_logs
        return 1
    }
}

stop_server() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    SERVER_PID=""
}

run_with_server() {
    local name="$1"
    local server_mode="$2"
    local client_mode="$3"
    local scenario="$4"
    local expect="${5:-pass}"
    local max_data="${6:-16777216}"
    local max_bidi="${7:-1024}"
    local max_uni="${8:-1024}"
    local extra="${9:-}"
    local server_extra="${10:-}"

    log "[ RUN      ] webtransport_draft15.$name"
    start_server "$server_mode" "$max_data" "$max_bidi" "$max_uni" "$server_extra"
    run_client_once "$name" "$scenario" "$client_mode" "$expect" "$extra"
    stop_server
    log "[       OK ] webtransport_draft15.$name"
}

main() {
    cd "$ROOT_DIR"

    ensure_binaries
    require_file "$CERT_FILE" "certificate"
    require_file "$KEY_FILE" "private key"
    pick_port

    log "WebTransport draft-15 C e2e"
    log "  server: $SERVER_BIN"
    log "  client: $CLIENT_BIN"
    log "  addr:   $HOST:$PORT"
    log "  scenarios: $SCENARIOS"
    log "  churn runs: $CLIENT_RUNS"
    log "  asan:   $ASAN"
    if [ "$ASAN" = "1" ]; then
        log "  sanitizers: $SANITIZERS"
    fi

    for scenario in $SCENARIOS; do
        case "$scenario" in
            bidi)
                run_with_server "bidi_echo" "draft15" "draft15" "bidi"
                ;;
            datagram)
                run_with_server "datagram_echo" "draft15" "draft15" "datagram"
                ;;
            large-datagram-reject)
                run_with_server "large_datagram_reject" "draft15" "draft15" "large-datagram-reject"
                ;;
            pre-session-datagram)
                run_with_server "pre_session_datagram" "draft15" "draft15" "pre-session-datagram"
                ;;
            pre-session-stream-overflow)
                run_with_server "pre_session_stream_overflow" "draft15" "draft15" "pre-session-stream-overflow"
                ;;
            close-gates)
                run_with_server "close_gates" "draft15" "draft15" "close-gates"
                ;;
            peer-close-fin)
                run_with_server "peer_close_fin" "draft15" "draft15" "peer-close-fin"
                ;;
            reset-prefix)
                run_with_server "reset_prefix" "draft15" "draft15" "reset-prefix"
                ;;
            server-bidi)
                run_with_server "server_bidi" "draft15" "draft15" "server-bidi"
                ;;
            multi-session)
                run_with_server "multi_session" "draft15" "draft15" "multi-session"
                ;;
            split-header)
                run_with_server "split_header" "draft15" "draft15" "split-header"
                ;;
            fc-data-blocked)
                run_with_server "fc_data_blocked" "draft15" "draft15" "fc-data-blocked" "pass" "16" "1024" "1024"
                ;;
            fc-stream-blocked)
                run_with_server "fc_stream_blocked" "draft15" "draft15" "fc-stream-blocked" "pass" "16777216" "0" "1024"
                ;;
            fc-disabled-single-session)
                run_with_server "fc_disabled_single_session" "draft15" "draft15" "fc-disabled-single-session" "pass" "0" "0" "0"
                ;;
            compat-legacy)
                run_with_server "compat_legacy" "legacy" "compat" "compat-legacy"
                ;;
            strict-reject-legacy)
                run_with_server "strict_reject_legacy" "legacy" "draft15" "strict-reject-legacy" "pass"
                ;;
            client-reject-missing-wt-enabled)
                run_with_server "client_reject_missing_wt_enabled" "draft15" "draft15" "client-reject-missing-wt-enabled" "pass" "16777216" "1024" "1024" "" "-x no-wt-enabled"
                ;;
            client-reject-missing-h3-datagram)
                run_with_server "client_reject_missing_h3_datagram" "draft15" "draft15" "client-reject-missing-h3-datagram" "pass" "16777216" "1024" "1024" "" "-x no-h3-datagram"
                ;;
            client-reject-missing-connect)
                run_with_server "client_reject_missing_connect" "draft15" "draft15" "client-reject-missing-connect" "pass" "16777216" "1024" "1024" "" "-x no-connect"
                ;;
            client-reject-missing-dgram-tp)
                run_with_server "client_reject_missing_dgram_tp" "draft15" "draft15" "client-reject-missing-dgram-tp" "pass" "16777216" "1024" "1024" "" "-x no-dgram-tp"
                ;;
            client-reject-missing-reset-at)
                run_with_server "client_reject_missing_reset_at" "draft15" "draft15" "client-reject-missing-reset-at" "pass" "16777216" "1024" "1024" "" "-x no-reset-at"
                ;;
            strict-missing-wt-enabled)
                run_with_server "strict_missing_wt_enabled" "draft15" "draft15" "strict-missing-wt-enabled"
                ;;
            strict-missing-h3-datagram)
                run_with_server "strict_missing_h3_datagram" "draft15" "draft15" "strict-missing-h3-datagram"
                ;;
            strict-missing-connect)
                run_with_server "strict_missing_connect" "draft15" "draft15" "strict-missing-connect"
                ;;
            strict-missing-dgram-tp)
                run_with_server "strict_missing_dgram_tp" "draft15" "draft15" "strict-missing-dgram-tp"
                ;;
            strict-missing-reset-at)
                run_with_server "strict_missing_reset_at" "draft15" "draft15" "strict-missing-reset-at"
                ;;
            invalid-datagram)
                run_with_server "invalid_datagram" "draft15" "draft15" "invalid-datagram"
                ;;
            churn)
                start_server "draft15" "16777216" "1024" "1024"
                log "[ RUN      ] webtransport_draft15.sequential_sessions"
                local i
                for i in $(seq 1 "$CLIENT_RUNS"); do
                    run_client_once "$i" "churn" "draft15"
                done
                stop_server
                log "[       OK ] webtransport_draft15.sequential_sessions"
                ;;
            *)
                log "unknown scenario: $scenario"
                return 1
                ;;
        esac
    done

}

main "$@"
