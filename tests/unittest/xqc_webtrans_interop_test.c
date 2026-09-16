/* Copyright (c) 2026, Alibaba Group Holding Limited. */

#include <xquic/xqc_webtransport.h>

static xqc_int_t xqc_wt_interop_test_send(xqc_wt_session_t *session,
    const void *data, size_t length, uint64_t *datagram_id);
static xqc_int_t xqc_wt_interop_test_close(xqc_wt_session_t *session,
    uint32_t error, const char *reason, size_t length);
static uint32_t xqc_wt_interop_test_error(xqc_wt_session_t *session);
static unsigned xqc_wt_interop_test_status(xqc_wt_session_t *session);

/* Replace transport IO only in this translation unit, not in the demo. */
#define xqc_wt_session_datagram_send xqc_wt_interop_test_send
#define xqc_wt_session_close_with_error xqc_wt_interop_test_close
#define xqc_wt_session_get_close_error_code xqc_wt_interop_test_error
#define xqc_wt_session_get_response_status xqc_wt_interop_test_status
#include "demo/xqc_webtrans_interop.c"
#undef xqc_wt_session_datagram_send
#undef xqc_wt_session_close_with_error
#undef xqc_wt_session_get_close_error_code
#undef xqc_wt_session_get_response_status
const xqc_demo_wt_app_policy_t xqc_demo_wt_echo_policy = {0};
#define XQC_ENABLE_WEBTRANSPORT_INTEROP 1
#include "demo/xqc_wt_app.c"
#undef XQC_ENABLE_WEBTRANSPORT_INTEROP
#include <dirent.h>
#include <CUnit/CUnit.h>
#include "xqc_webtrans_interop_test.h"
#include "xqc_common_test.h"
#include "src/webtransport/xqc_webtransport_ctx.h"
#include "src/webtransport/xqc_webtransport_conn.h"
#include "src/webtransport/xqc_webtransport_session.h"
#include "src/webtransport/xqc_webtransport_dgram.h"
#include "src/http3/xqc_h3_ctx.h"
#include "src/http3/xqc_h3_conn.h"
#include "src/transport/xqc_conn.h"

#define xqc_wt_interop_check(condition, message) \
    CU_assertImplementation((condition), __LINE__, (message), __FILE__, \
                            "", CU_TRUE)

static int xqc_wt_interop_test_result;
static int xqc_wt_interop_test_sends;
static int xqc_wt_interop_test_accepts;
static int xqc_wt_interop_test_sequence;
static int xqc_wt_interop_test_close_on_send;
static int xqc_wt_interop_test_scheduled;
static int xqc_wt_interop_test_closes;
static uint32_t xqc_wt_interop_test_code;
static unsigned char xqc_wt_interop_test_payload[XQC_WT_INTEROP_DATAGRAM_MAX];
static size_t xqc_wt_interop_test_length;
static size_t xqc_wt_interop_test_early_reads;

static void xqc_wt_interop_test_schedule(void *data);
static void xqc_wt_interop_test_reset(void);
static void xqc_wt_interop_test_clear(void);
static void xqc_wt_interop_test_fixture(char *directory);
static void xqc_wt_interop_test_remove(const char *directory);
static void xqc_wt_interop_test_early(xqc_wt_session_t *session,
    const void *data, size_t length, void *user_data, uint64_t time);

void
xqc_test_wt_interop_policy(void)
{
    CU_ASSERT(xqc_wt_interop_policy.require_webtransport);
    CU_ASSERT(!xqc_wt_interop_policy.allow_case_id);
    CU_ASSERT(xqc_wt_interop_policy.allow_remote_certificate);
    CU_ASSERT(!xqc_wt_interop_policy.allow_client_probe);
    CU_ASSERT_PTR_NULL(xqc_wt_interop_policy.server_init);
}

void
xqc_test_wt_app_select(void)
{
    char *saved_role = getenv("ROLE") ? strdup(getenv("ROLE")) : NULL;
    char *saved_case = getenv("TESTCASE")
        ? strdup(getenv("TESTCASE")) : NULL;

    unsetenv("ROLE");
    unsetenv("TESTCASE");
    CU_ASSERT(xqc_demo_wt_app_select(0) == 0);
    CU_ASSERT(!xqc_demo_wt_app_is_interop());
    CU_ASSERT(xqc_demo_wt_app_policy == &xqc_demo_wt_echo_policy);

    setenv("ROLE", "client", 1);
    setenv("TESTCASE", "transfer-datagram-receive", 1);
    CU_ASSERT(xqc_demo_wt_app_select(0) == 0);
    CU_ASSERT(xqc_demo_wt_app_is_interop());
    CU_ASSERT(xqc_demo_wt_app_policy == &xqc_wt_interop_policy);

    setenv("ROLE", "server", 1);
    setenv("TESTCASE", "transfer-bidirectional-send", 1);
    CU_ASSERT(xqc_demo_wt_app_select(1) == 0);
    CU_ASSERT(xqc_demo_wt_app_is_interop());

    if (saved_role) {
        setenv("ROLE", saved_role, 1);
    } else {
        unsetenv("ROLE");
    }
    if (saved_case) {
        setenv("TESTCASE", saved_case, 1);
    } else {
        unsetenv("TESTCASE");
    }
    free(saved_role);
    free(saved_case);
}

void
xqc_test_wt_app_reject(void)
{
    char *saved_role = getenv("ROLE") ? strdup(getenv("ROLE")) : NULL;
    char *saved_case = getenv("TESTCASE")
        ? strdup(getenv("TESTCASE")) : NULL;

    setenv("ROLE", "client", 1);
    unsetenv("TESTCASE");
    CU_ASSERT(xqc_demo_wt_app_select(0) < 0);
    CU_ASSERT(!xqc_demo_wt_app_is_interop());
    setenv("TESTCASE", "transfer-unidirectional-send", 1);
    CU_ASSERT(xqc_demo_wt_app_select(0) < 0);
    CU_ASSERT(xqc_demo_wt_app_policy == &xqc_demo_wt_echo_policy);
    setenv("ROLE", "server", 1);
    setenv("TESTCASE", "unknown", 1);
    CU_ASSERT(xqc_demo_wt_app_select(1) < 0);
    CU_ASSERT(!xqc_demo_wt_app_is_interop());

    if (saved_role) {
        setenv("ROLE", saved_role, 1);
    } else {
        unsetenv("ROLE");
    }
    if (saved_case) {
        setenv("TESTCASE", saved_case, 1);
    } else {
        unsetenv("TESTCASE");
    }
    free(saved_role);
    free(saved_case);
}

static xqc_int_t
xqc_wt_interop_test_send(xqc_wt_session_t *session, const void *data,
    size_t length, uint64_t *datagram_id)
{
    int result = xqc_wt_interop_test_accepts
                 ? xqc_wt_interop_test_result : -XQC_EAGAIN;

    CU_ASSERT(length <= sizeof(xqc_wt_interop_test_payload));
    xqc_wt_interop_test_length = length;
    if (length <= sizeof(xqc_wt_interop_test_payload)) {
        memcpy(xqc_wt_interop_test_payload, data, length);
    }
    xqc_wt_interop_test_sends++;
    if (xqc_wt_interop_test_sequence >= 0) {
        uint32_t sequence = 0;
        CU_ASSERT(length == sizeof(sequence));
        if (length == sizeof(sequence)) {
            memcpy(&sequence, data, length);
        }
        CU_ASSERT(sequence == (uint32_t) xqc_wt_interop_test_sequence);
        if (result == XQC_OK) {
            xqc_wt_interop_test_sequence++;
        }
    }
    if (result == XQC_OK && xqc_wt_interop_test_accepts > 0) {
        xqc_wt_interop_test_accepts--;
    }
    if (xqc_wt_interop_test_close_on_send) {
        xqc_wt_interop_closed(session, NULL, NULL, NULL);
        xqc_wt_interop_test_close_on_send = 0;
        xqc_wt_interop_test_result = XQC_ERROR;
    }
    return result;
}

static xqc_int_t
xqc_wt_interop_test_close(xqc_wt_session_t *session, uint32_t error,
    const char *reason, size_t length)
{
    xqc_wt_interop_test_closes++;
    xqc_wt_interop_test_code = error;
    return XQC_OK;
}

static uint32_t
xqc_wt_interop_test_error(xqc_wt_session_t *session)
{
    return xqc_wt_interop_test_code;
}

static unsigned
xqc_wt_interop_test_status(xqc_wt_session_t *session)
{
    return 200;
}

static void
xqc_wt_interop_test_schedule(void *data)
{
    xqc_wt_interop_test_scheduled++;
}

static void
xqc_wt_interop_test_reset(void)
{
    memset(&xqc_wt_interop, 0, sizeof(xqc_wt_interop));
    xqc_wt_interop.root = -1;
    xqc_wt_interop.directory = -1;
    xqc_wt_interop.schedule_send = xqc_wt_interop_test_schedule;
    xqc_wt_interop.case_name = "unit";
    xqc_wt_interop_test_result = XQC_OK;
    xqc_wt_interop_test_sends = 0;
    xqc_wt_interop_test_accepts = -1;
    xqc_wt_interop_test_sequence = -1;
    xqc_wt_interop_test_close_on_send = 0;
    xqc_wt_interop_test_scheduled = 0;
    xqc_wt_interop_test_closes = 0;
    xqc_wt_interop_test_code = 0;
}

static void
xqc_wt_interop_test_clear(void)
{
    while (xqc_wt_interop.streams) {
        xqc_wt_interop_free_stream(xqc_wt_interop.streams);
    }
    free(xqc_wt_interop.requests_storage);
    free(xqc_wt_interop.protocol_storage);
    if (xqc_wt_interop.directory >= 0) {
        close(xqc_wt_interop.directory);
    }
    if (xqc_wt_interop.root >= 0) {
        close(xqc_wt_interop.root);
    }
    xqc_wt_interop_test_reset();
}

static void
xqc_wt_interop_test_fixture(char *directory)
{
    xqc_wt_interop_test_reset();
    xqc_wt_interop_check(mkdtemp(directory) != NULL, "create transfer fixture");
    xqc_wt_interop.root = open(directory, O_RDONLY | O_DIRECTORY);
    xqc_wt_interop_check(xqc_wt_interop.root >= 0, "open transfer fixture");
    xqc_wt_interop_check(mkdirat(xqc_wt_interop.root, "wt", 0755) == 0,
                         "create session directory");
    xqc_wt_interop.directory = openat(xqc_wt_interop.root, "wt",
                                      O_RDONLY | O_DIRECTORY);
    xqc_wt_interop_check(xqc_wt_interop.directory >= 0,
                         "open session directory");
}

static void
xqc_wt_interop_test_remove(const char *directory)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/wt", directory);
    DIR *files = opendir(path);
    if (files) {
        struct dirent *entry;
        while ((entry = readdir(files))) {
            if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
                CU_ASSERT(unlinkat(dirfd(files), entry->d_name, 0) == 0);
            }
        }
        closedir(files);
    }
    CU_ASSERT(rmdir(path) == 0);
    CU_ASSERT(rmdir(directory) == 0);
}

static void
xqc_wt_interop_test_early(xqc_wt_session_t *session, const void *data,
    size_t length, void *user_data, uint64_t time)
{
    char expected[32];
    size_t size = snprintf(expected, sizeof(expected), "GET file-%zu",
                            xqc_wt_interop_test_early_reads++);
    CU_ASSERT(length == size && !memcmp(data, expected, size));
}

void
xqc_test_wt_interop_paths(void)
{
    const char *invalid[] = {"", "/file", "../file", "a/../b", "a/./b",
        "a//b", "a/", "a\\b", "a%2fb", "a?b", "a\nb", "a:b"};
    char boundary[257];

    xqc_wt_interop_check(xqc_wt_interop_valid_path("nested/a-1.bin"),
                         "safe nested path");
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        xqc_wt_interop_check(!xqc_wt_interop_valid_path(invalid[i]),
                             "reject path escape or invalid character");
    }
    memset(boundary, 'a', sizeof(boundary));
    boundary[255] = '\0';
    xqc_wt_interop_check(xqc_wt_interop_valid_path(boundary),
                         "255-byte component accepted");
    boundary[255] = 'a';
    boundary[256] = '\0';
    xqc_wt_interop_check(!xqc_wt_interop_valid_path(boundary),
                         "256-byte component rejected");
}

void
xqc_test_wt_interop_headers(void)
{
    const char get[] = "GET nested/file.bin";
    const char push[] = "PUSH nested/file.bin\n\0\xffpayload";
    const char *invalid[] = {"GET ../escape", "GET /absolute", "GET file\n",
        "GET ", "PUT file", "GET a\\b"};
    size_t consumed;

    /* The runner's GET ends at FIN; PUSH separates its binary body with LF. */
    for (size_t split = 0; split < strlen(get); split++) {
        xqc_wt_interop_header_t header = {0};
        xqc_wt_interop_check(xqc_wt_interop_header_feed(&header,
            get, split, 0, 0, &consumed) == 0 && consumed == split,
            "fragmented GET waits for FIN");
        xqc_wt_interop_check(xqc_wt_interop_header_feed(&header,
            get + split, strlen(get) - split, 1, 0, &consumed) == 1,
            "fragmented GET completes at FIN");
    }
    size_t line_length = strlen("PUSH nested/file.bin\n");
    for (size_t split = 0; split < line_length; split++) {
        xqc_wt_interop_header_t header = {0};
        xqc_wt_interop_check(xqc_wt_interop_header_feed(&header,
            push, split, 0, 1, &consumed) == 0,
            "fragmented PUSH waits for LF");
        xqc_wt_interop_check(xqc_wt_interop_header_feed(&header,
            push + split, sizeof(push) - 1 - split, 1, 1, &consumed) == 1
            && consumed == line_length - split,
            "PUSH consumes only header before binary body");
    }
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        xqc_wt_interop_header_t header = {0};
        xqc_wt_interop_check(xqc_wt_interop_header_feed(&header,
            invalid[i], strlen(invalid[i]), 1, 0, &consumed) == -1,
            "malformed GET rejected");
    }
    xqc_wt_interop_header_t header = {0};
    xqc_wt_interop_check(xqc_wt_interop_header_feed(&header,
        "PUSH file", 9, 1, 1, &consumed) == -1,
        "FIN before PUSH header LF rejected");
    memset(&header, 0, sizeof(header));
    char oversized[2048];
    memset(oversized, 'a', sizeof(oversized));
    xqc_wt_interop_check(xqc_wt_interop_header_feed(&header,
        oversized, sizeof(oversized), 0, 0, &consumed) == -1,
        "bounded header rejects oversized fragment");
}


void
xqc_test_wt_interop_file_confinement(void)
{
    char directory[] = "/tmp/xqc-wt-interop-unit-XXXXXX";
    char *root = mkdtemp(directory);

    xqc_wt_interop_check(root != NULL, "create isolated fixture directory");
    int parent = open(root, O_RDONLY | O_DIRECTORY);
    xqc_wt_interop_check(parent >= 0, "open fixture root");
    int file = xqc_wt_interop_open_file(parent, "nested/file.bin", 1);
    xqc_wt_interop_check(file >= 0 && write(file, "\0\xff", 2) == 2,
        "write confined nested binary file");
    close(file);
    file = xqc_wt_interop_open_file(parent, "nested/file.bin", 0);
    unsigned char bytes[2];
    xqc_wt_interop_check(file >= 0 && read(file, bytes, 2) == 2
        && bytes[0] == 0 && bytes[1] == 0xff,
        "read exact confined binary file");
    close(file);
    xqc_wt_interop_check(xqc_wt_interop_open_file(parent,
        "nested/file.bin", 1) < 0, "do not overwrite existing download");
    xqc_wt_interop_check(xqc_wt_interop_open_file(parent,
        "../escape.bin", 1) < 0, "reject parent traversal");
    xqc_wt_interop_check(symlinkat("nested", parent, "alias") == 0,
        "create directory symlink fixture");
    xqc_wt_interop_check(xqc_wt_interop_open_file(parent,
        "alias/file.bin", 0) < 0, "do not follow directory symlink");
    xqc_wt_interop_check(symlinkat("nested/file.bin", parent, "link") == 0,
        "create leaf symlink fixture");
    xqc_wt_interop_check(xqc_wt_interop_open_file(parent, "link", 0) < 0,
        "do not follow source file symlink");
    unlinkat(parent, "link", 0);
    unlinkat(parent, "alias", 0);
    unlinkat(parent, "nested/file.bin", 0);
    unlinkat(parent, "nested", AT_REMOVEDIR);
    close(parent);
    rmdir(root);
}

void
xqc_test_wt_interop_roles(void)
{
    const char *variables[] = {"ROLE", "TESTCASE", "REQUESTS", "PROTOCOLS",
        "XQC_WT_WWW", "XQC_WT_DOWNLOADS"};
    char *saved[6];
    char directory[] = "/tmp/xqc-wt-roles-XXXXXX";
    char requests[16384];
    struct {
        int server;
        const char *role;
        const char *testcase;
        const char *requests;
        int mode;
        int valid;
    } cases[] = {
        {0, "client", "transfer", "https://server/wt", 0, 1},
        {0, "client", "handshake", "https://server/wt", 0, 1},
        {0, "client", "transfer-unidirectional-receive",
         "https://server/wt/a", 1, 1},
        {0, "client", "transfer-bidirectional-receive",
         "https://server/wt/a", 2, 1},
        {1, "server", "transfer-unidirectional-send", "wt/a wt/b", 1, 1},
        {1, "server", "transfer-bidirectional-send", "wt/a wt/b", 2, 1},
        {1, "client", "transfer", "wt", 0, 0},
        {0, "client", "transfer-bidirectional-send", "https://server/wt/a",
         0, 0},
        {1, "server", "transfer-datagram-receive", "wt/a", 0, 0},
        {0, "client", "transfer", "https://server/wt/a", 0, 0},
        {0, "client", "transfer", "   ", 0, 0},
        {0, "client", "transfer-datagram-receive",
         "https://other/wt/a", 3, 0},
        {0, "client", "transfer-datagram-receive",
         "https://server/wt/a https://server/wt/a", 3, 0},
        {1, "server", "transfer-datagram-send", "wt/a wt/a", 3, 0},
        {1, "server", "transfer-datagram-send", "https://server/wt/a", 3, 0},
        {1, "server", "transfer-datagram-send", "wt/../a", 3, 0},
        {1, "server", "transfer-datagram-send", "other/a", 3, 0},
    };

    for (size_t i = 0; i < 6; i++) {
        const char *value = getenv(variables[i]);
        saved[i] = value ? strdup(value) : NULL;
    }
    xqc_wt_interop_test_fixture(directory);
    xqc_wt_interop_test_clear();
    setenv("PROTOCOLS", "files", 1);
    setenv("XQC_WT_WWW", directory, 1);
    setenv("XQC_WT_DOWNLOADS", directory, 1);
    setenv("ROLE", "client", 1);
    setenv("TESTCASE", "transfer", 1);
    xqc_engine_t *engine = test_create_engine();
    xqc_wt_interop_check(engine != NULL, "create interop policy engine");
    CU_ASSERT(xqc_wt_interop_init(engine, 16, 0,
        xqc_wt_interop_test_schedule, NULL, NULL) == XQC_OK);
    xqc_wt_ctx_t *ctx = xqc_wt_ctx_get(engine);
    xqc_wt_interop_check(ctx != NULL, "initialize actual interop context");
    CU_ASSERT(ctx->pending_count_max == XQC_WT_INTEROP_FILES_MAX);
    CU_ASSERT(ctx->pending_bytes_max
        == XQC_WT_INTEROP_FILES_MAX * XQC_WT_INTEROP_DATAGRAM_MAX);
    CU_ASSERT(ctx->pending_window
        == XQC_WEBTRANSPORT_DEFAULT_UNKNOWN_SESSION_DGRAM_WINDOW);
    ctx->dgram_cbs.dgram_read_notify = xqc_wt_interop_test_early;
    xqc_connection_t transport = {0};
    xqc_h3_conn_t h3c = {.conn = &transport};
    xqc_wt_conn_t *conn = xqc_wt_conn_create(&h3c);
    xqc_wt_interop_check(conn != NULL, "create pending-session connection");
    conn->ctx = ctx;
    conn->negotiated_version = XQC_WEBTRANSPORT_DRAFT_VERSION_16;
    transport.proto_data = &h3c;
    xqc_wt_session_t *session = xqc_wt_session_init(0, conn, NULL);
    xqc_wt_interop_check(session != NULL, "create unopened session");
    xqc_datagram_callbacks_t cbs = {0};
    xqc_wt_dgram_callbacks(&cbs);
    xqc_wt_interop_test_early_reads = 0;
    size_t pending_bytes = 0;
    /* CONNECT response ordering must not truncate the runner's 200 GETs. */
    for (size_t i = 0; i < 200; i++) {
        char request[32] = {0};
        size_t length = snprintf(request + 1, sizeof(request) - 1,
                                  "GET file-%zu", i);
        pending_bytes += length;
        cbs.datagram_read_notify(&transport, NULL, request, length + 1, 0);
    }
    printf("WT early datagram fixture: offered=200 buffered=%zu bytes=%zu\n",
           conn->pending_count, conn->pending_bytes);
    CU_ASSERT(!xqc_wt_interop_test_early_reads && conn->pending_count == 200);
    CU_ASSERT(conn->pending_bytes == pending_bytes);
    session->open = XQC_TRUE;
    xqc_wt_dgram_resume(session);
    CU_ASSERT(xqc_wt_interop_test_early_reads == 200);
    CU_ASSERT(!conn->pending_count && !conn->pending_bytes);
    session->close_notified = XQC_TRUE;
    xqc_wt_conn_destroy(conn);
    xqc_wt_interop_test_clear();
    xqc_h3_ctx_destroy(engine);
    xqc_engine_destroy(engine);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        setenv("ROLE", cases[i].role, 1);
        setenv("TESTCASE", cases[i].testcase, 1);
        setenv("REQUESTS", cases[i].requests, 1);
        xqc_wt_interop.server = cases[i].server;
        strcpy(xqc_wt_interop.endpoint, "wt");
        int result = xqc_wt_interop_configure(cases[i].server);
        if (!result) {
            result = xqc_wt_interop_requests("server", "/wt");
        }
        CU_ASSERT((result == 0) == cases[i].valid);
        if (cases[i].valid) {
            CU_ASSERT(xqc_wt_interop.mode == cases[i].mode);
            CU_ASSERT(xqc_wt_interop.file_count
                == (cases[i].mode ? cases[i].server ? 2 : 1 : 0));
            for (size_t n = 0; n < xqc_wt_interop.file_count; n++) {
                uintptr_t file = (uintptr_t) xqc_wt_interop.files[n];
                uintptr_t storage =
                    (uintptr_t) xqc_wt_interop.requests_storage;
                CU_ASSERT(file >= storage
                    && file < storage + strlen(cases[i].requests) + 1);
            }
        }
        xqc_wt_interop_test_clear();
    }
    setenv("ROLE", "client", 1);
    setenv("TESTCASE", "transfer-unidirectional-receive", 1);
    setenv("REQUESTS", "https://server/wt/first https://server/wt/first", 1);
    CU_ASSERT(xqc_wt_interop_configure(0) == 0);
    CU_ASSERT(xqc_wt_interop_requests("server", "/wt") < 0);
    CU_ASSERT(xqc_wt_interop.file_count == 1);
    CU_ASSERT_STRING_EQUAL(xqc_wt_interop.files[0], "first");
    setenv("REQUESTS", "replaced", 1);
    CU_ASSERT_STRING_EQUAL(xqc_wt_interop.files[0], "first");
    xqc_wt_interop.failed = 1;
    CU_ASSERT(xqc_wt_interop_client_finish() == 1);
    CU_ASSERT(xqc_wt_interop.requests_storage == NULL);
    CU_ASSERT(xqc_wt_interop_client_finish() == 1);
    xqc_wt_interop_test_clear();

    for (int server = 0; server < 2; server++) {
        for (size_t count = 200; count <= 257; count += count == 200 ? 56 : 1) {
            size_t length = 0;
            for (size_t i = 0; i < count; i++) {
                int written = snprintf(requests + length,
                    sizeof(requests) - length, "%swt/file-%zu ",
                    server ? "" : "https://server/", i);
                if (written < 0
                    || (size_t) written >= sizeof(requests) - length)
                {
                    CU_FAIL("request fixture exceeds buffer");
                    goto restore_environment;
                }
                length += (size_t) written;
            }
            setenv("ROLE", server ? "server" : "client", 1);
            setenv("TESTCASE", server ? "transfer-datagram-send"
                                     : "transfer-datagram-receive", 1);
            setenv("REQUESTS", requests, 1);
            xqc_wt_interop.server = server;
            strcpy(xqc_wt_interop.endpoint, "wt");
            CU_ASSERT(xqc_wt_interop_configure(server) == 0);
            int result = xqc_wt_interop_requests("server", "/wt");
            CU_ASSERT((result == 0) == (count <= XQC_WT_INTEROP_FILES_MAX));
            if (!result) {
                CU_ASSERT(xqc_wt_interop.file_count == count);
                CU_ASSERT_STRING_EQUAL(xqc_wt_interop.files[199], "file-199");
                CU_ASSERT_STRING_EQUAL(xqc_wt_interop.case_name,
                                       server ? "DS" : "DR");
            }
            xqc_wt_interop_test_clear();
        }
    }
restore_environment:
    for (size_t i = 0; i < 6; i++) {
        if (saved[i]) {
            setenv(variables[i], saved[i], 1);
        } else {
            unsetenv(variables[i]);
        }
        free(saved[i]);
    }
    xqc_wt_interop_test_remove(directory);

    for (int mode = 1; mode <= 3; mode++) {
        xqc_wt_interop.server = 1;
        xqc_wt_interop.mode = mode;
        xqc_wt_interop_test_code = 1;
        xqc_wt_interop_closed(NULL, NULL, NULL, NULL);
        CU_ASSERT(xqc_wt_interop.failed && !xqc_wt_interop.success);
        xqc_wt_interop_test_clear();
    }
    xqc_wt_interop.completed = 200;
    xqc_wt_interop_closed(NULL, NULL, NULL, NULL);
    CU_ASSERT(xqc_wt_interop.success && !xqc_wt_interop.failed);
    xqc_wt_interop_test_clear();
}


void
xqc_test_wt_interop_peer_close_complete(void)
{
    xqc_wt_interop_test_reset();
    xqc_wt_interop.finished = xqc_wt_interop_test_schedule;
    xqc_wt_interop.completed = 5;
    xqc_wt_interop_client_conn_closing(NULL, NULL, XQC_OK, NULL);
    CU_ASSERT(xqc_wt_interop.success && !xqc_wt_interop.failed);
    CU_ASSERT(xqc_wt_interop_test_scheduled == 1);
    xqc_wt_interop_test_clear();

    xqc_wt_interop.completed = 5;
    xqc_wt_interop_test_code = 1;
    xqc_wt_interop_closed(NULL, NULL, NULL, NULL);
    CU_ASSERT(xqc_wt_interop.success && !xqc_wt_interop.failed);
    xqc_wt_interop_test_clear();
}

void
xqc_test_wt_interop_peer_close_incomplete(void)
{
    xqc_wt_interop_test_reset();
    xqc_wt_interop_client_conn_closing(NULL, NULL, XQC_OK, NULL);
    CU_ASSERT(xqc_wt_interop.failed && !xqc_wt_interop.success);
    xqc_wt_interop_test_clear();

    xqc_wt_interop.completed = 1;
    CU_ASSERT(xqc_wt_interop_datagram_queue("pending", 7) == XQC_OK);
    xqc_wt_interop_client_conn_closing(NULL, NULL, XQC_OK, NULL);
    CU_ASSERT(xqc_wt_interop.failed && !xqc_wt_interop.success);
    xqc_wt_interop_test_clear();

    xqc_wt_interop.completed = 1;
    CU_ASSERT(xqc_wt_interop_allocate(NULL) != NULL);
    xqc_wt_interop_client_conn_closing(NULL, NULL, XQC_OK, NULL);
    CU_ASSERT(xqc_wt_interop.failed && !xqc_wt_interop.success);
    xqc_wt_interop_test_clear();

    xqc_wt_interop.completed = 1;
    xqc_wt_interop_client_conn_closing(NULL, NULL, XQC_ERROR, NULL);
    CU_ASSERT(xqc_wt_interop.failed && !xqc_wt_interop.success);
    xqc_wt_interop_test_clear();
}

void
xqc_test_wt_interop_datagram_backpressure(void)
{
    const unsigned char payload[] = "PUSH file\n\0\xff" "data";
    const int blocked[] = {-XQC_EAGAIN, -XQC_ECONN_BLOCKED,
        -XQC_ESTREAM_BLOCKED};
    unsigned char oversized[XQC_WT_INTEROP_DATAGRAM_MAX + 1] = {0};
    xqc_wt_interop_datagram_t *item;

    xqc_wt_interop_test_reset();
    xqc_wt_interop_datagram_write(NULL, NULL);
    CU_ASSERT(!xqc_wt_interop_test_scheduled && !xqc_wt_interop_test_sends);
    for (size_t i = 0; i < sizeof(blocked) / sizeof(blocked[0]); i++) {
        CU_ASSERT(xqc_wt_interop_datagram_queue(payload, sizeof(payload) - 1)
                  == XQC_OK);
        item = &xqc_wt_interop.datagrams[xqc_wt_interop.datagram_head];
        xqc_wt_interop_test_result = blocked[i];
        xqc_wt_interop_datagram_write(NULL, NULL);
        CU_ASSERT(!xqc_wt_interop.failed && !xqc_wt_interop.completed);
        CU_ASSERT(&xqc_wt_interop.datagrams[xqc_wt_interop.datagram_head]
            == item && xqc_wt_interop.datagram_count == 1);
        CU_ASSERT(item->length == sizeof(payload) - 1
            && !memcmp(item->data, payload, sizeof(payload) - 1));
        CU_ASSERT(xqc_wt_interop_test_length == item->length);
        CU_ASSERT(!memcmp(xqc_wt_interop_test_payload, payload,
                           sizeof(payload) - 1));
        xqc_wt_interop_test_result = XQC_OK;
        xqc_wt_interop_datagram_write(NULL, NULL);
        CU_ASSERT(!xqc_wt_interop.datagram_count);
        CU_ASSERT(xqc_wt_interop.datagram_head == 1);
        CU_ASSERT(xqc_wt_interop.completed == 1
            && xqc_wt_interop_test_sends == 2);
        CU_ASSERT(!memcmp(xqc_wt_interop_test_payload, payload,
                           sizeof(payload) - 1));
        xqc_wt_interop_test_clear();
    }
    CU_ASSERT(xqc_wt_interop_datagram_queue(payload, sizeof(payload) - 1)
              == XQC_OK);
    item = &xqc_wt_interop.datagrams[xqc_wt_interop.datagram_head];
    xqc_wt_interop.success = 1;
    xqc_wt_interop_datagram_write(NULL, NULL);
    CU_ASSERT(!xqc_wt_interop_test_sends && !xqc_wt_interop_test_scheduled);
    xqc_wt_interop.success = 0;
    xqc_wt_interop_test_result = XQC_ERROR;
    xqc_wt_interop_datagram_write(NULL, NULL);
    CU_ASSERT(xqc_wt_interop.failed
        && &xqc_wt_interop.datagrams[xqc_wt_interop.datagram_head] == item);
    CU_ASSERT(!xqc_wt_interop.completed);
    int scheduled = xqc_wt_interop_test_scheduled;
    xqc_wt_interop_datagram_write(NULL, NULL);
    CU_ASSERT(xqc_wt_interop_test_sends == 1
        && xqc_wt_interop_test_scheduled == scheduled);
    xqc_wt_interop_test_clear();

    for (size_t i = 0; i < XQC_WT_INTEROP_FILES_MAX; i++) {
        CU_ASSERT(xqc_wt_interop_datagram_queue(payload, sizeof(payload) - 1)
                  == XQC_OK);
    }
    CU_ASSERT(xqc_wt_interop_datagram_queue(payload, sizeof(payload) - 1)
              == XQC_ERROR);
    CU_ASSERT(xqc_wt_interop.failed
        && xqc_wt_interop.datagram_count == XQC_WT_INTEROP_FILES_MAX);
    xqc_wt_interop_test_clear();
    CU_ASSERT(xqc_wt_interop_datagram_queue(oversized,
        XQC_WT_INTEROP_DATAGRAM_MAX) == XQC_OK);
    item = &xqc_wt_interop.datagrams[xqc_wt_interop.datagram_head];
    CU_ASSERT(item->length == XQC_WT_INTEROP_DATAGRAM_MAX);
    xqc_wt_interop_test_clear();
    CU_ASSERT(xqc_wt_interop_datagram_queue(oversized, sizeof(oversized))
              == XQC_ERROR);
    CU_ASSERT(xqc_wt_interop.failed && !xqc_wt_interop.datagram_count);
    xqc_wt_interop_test_clear();

    xqc_wt_interop.mode = 3;
    xqc_wt_interop.file_count = 1;
    xqc_wt_interop.files[0] = "blocked";
    xqc_wt_interop_test_result = -XQC_EAGAIN;
    CU_ASSERT(xqc_wt_interop_datagram_request(NULL) == XQC_OK);
    item = &xqc_wt_interop.datagrams[xqc_wt_interop.datagram_head];
    CU_ASSERT(xqc_wt_interop.datagram_count == 1 && item->length == 11);
    CU_ASSERT(!memcmp(item->data, "GET blocked", 11));
    xqc_wt_interop_test_result = XQC_OK;
    xqc_wt_interop_datagram_write(NULL, NULL);
    CU_ASSERT(!xqc_wt_interop.datagram_count && !xqc_wt_interop.completed);
    CU_ASSERT(xqc_wt_interop_test_sends == 2);
    CU_ASSERT(xqc_wt_interop_test_length == 11
        && !memcmp(xqc_wt_interop_test_payload, "GET blocked", 11));
    xqc_wt_interop_test_clear();
    for (int guard = 0; guard < 4; guard++) {
        xqc_wt_interop.file_count = 1;
        xqc_wt_interop.files[0] = "stopped";
        xqc_wt_interop.failed = guard == 0;
        xqc_wt_interop.success = guard == 1;
        xqc_wt_interop.stopped = guard == 2;
        xqc_wt_interop.completed = guard == 3;
        CU_ASSERT(xqc_wt_interop_datagram_request(NULL) == XQC_OK);
        CU_ASSERT(!xqc_wt_interop_test_sends && !xqc_wt_interop.datagram_count);
        xqc_wt_interop_test_clear();
    }

    /* Refill across the ring boundary while a partially drained head blocks. */
    xqc_wt_interop_test_sequence = 0;
    for (uint32_t i = 0; i < 8; i++) {
        CU_ASSERT(xqc_wt_interop_datagram_queue(&i, sizeof(i)) == XQC_OK);
    }
    xqc_wt_interop_datagram_write(NULL, NULL);
    CU_ASSERT(xqc_wt_interop.datagram_head == 8
        && !xqc_wt_interop.datagram_count);
    for (uint32_t i = 8; i < 264; i++) {
        CU_ASSERT(xqc_wt_interop_datagram_queue(&i, sizeof(i)) == XQC_OK);
    }
    CU_ASSERT(xqc_wt_interop.datagram_count == XQC_WT_INTEROP_FILES_MAX);
    xqc_wt_interop_test_accepts = 3;
    xqc_wt_interop_datagram_write(NULL, NULL);
    CU_ASSERT(xqc_wt_interop.datagram_head == 11
        && xqc_wt_interop.datagram_count == 253);
    item = &xqc_wt_interop.datagrams[xqc_wt_interop.datagram_head];
    uint32_t blocked_sequence = 11;
    CU_ASSERT(item->length == sizeof(blocked_sequence)
        && !memcmp(item->data, &blocked_sequence, sizeof(blocked_sequence)));
    for (uint32_t i = 264; i < 267; i++) {
        CU_ASSERT(xqc_wt_interop_datagram_queue(&i, sizeof(i)) == XQC_OK);
    }
    CU_ASSERT(xqc_wt_interop.datagram_count == XQC_WT_INTEROP_FILES_MAX);
    CU_ASSERT(item->length == sizeof(blocked_sequence)
        && !memcmp(item->data, &blocked_sequence, sizeof(blocked_sequence)));
    xqc_wt_interop_test_accepts = -1;
    xqc_wt_interop_datagram_write(NULL, NULL);
    CU_ASSERT(!xqc_wt_interop.failed && !xqc_wt_interop.datagram_count);
    CU_ASSERT(xqc_wt_interop.datagram_head == 11);
    CU_ASSERT(xqc_wt_interop.completed == 267
        && xqc_wt_interop_test_sequence == 267);
    CU_ASSERT(xqc_wt_interop_test_sends == 268);
    xqc_wt_interop_test_clear();

    xqc_wt_session_t session = {0};
    xqc_wt_interop.session = &session;
    xqc_wt_interop.server = 1;
    xqc_wt_interop.datagram_head = 8;
    xqc_wt_interop_test_close_on_send = 1;
    for (int i = 0; i < 2; i++) {
        CU_ASSERT(xqc_wt_interop_datagram_queue(payload, sizeof(payload) - 1)
                  == XQC_OK);
    }
    xqc_wt_interop_datagram_write(&session, NULL);
    CU_ASSERT(!xqc_wt_interop.session && !xqc_wt_interop.datagram_count
        && !xqc_wt_interop.datagram_head && !xqc_wt_interop.completed);
    CU_ASSERT(xqc_wt_interop_test_sends == 1
        && !xqc_wt_interop_test_scheduled);
    xqc_wt_interop_datagram_write(&session, NULL);
    CU_ASSERT(xqc_wt_interop_test_sends == 1);
    xqc_wt_interop_test_clear();
}
