/* Copyright (c) 2026, Alibaba Group Holding Limited. */

/* Exercise the same private application helpers used by both demo roles. */
#include "demo/xqc_webtrans_interop.c"
#include <CUnit/CUnit.h>
#include "xqc_webtrans_interop_test.h"

#define xqc_wt_interop_check(condition, message) \
    CU_assertImplementation((condition), __LINE__, (message), __FILE__, \
                            "", CU_TRUE)

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
xqc_test_wt_interop_protocols(void)
{
    const char *protocols[] = {"server-first", "client-first", "a\"b\\c"};
    const char *valid[] = {"\"client-first\", \"server-first\"",
        " \"client-first\";ignored=\"x,y\", \"server-first\" ",
        "\"client-first\";flag;version=7;raw=:YQ==:",
        ("\"client-first\";display=%\"caf%c3%a9\";flag=?0;date=@-5"
         ";decimal=-1.25;token=*a:/;raw=:AQI:;empty=::;text=\"a\\\"b\""),
        "\"other\",\t\"client-first\"\t"};
    const char *invalid[] = {"client-first", "\"client-first\",",
        "\"client-first\" garbage", "\"client-first\";=1",
        "\"client-first\";value=", "\"unterminated",
        "\"bad\\escape\"", "\"client-first\", unquoted",
        "\"client-first\";bad=?7", "\"client-first\";bad=1.1234",
        "\"client-first\";bad=-", "\"client-first\";bad=@",
        "\"client-first\";bad=:a:", "\"client-first\";bad=:AQ=I:",
        "\"client-first\";bad=:AQI===:", "\"client-first\";bad=:AQI",
        "\"client-first\";bad=%\"%ff\"",
        "\"client-first\";bad=%\"%e2%82\"",
        "\"client-first\";bad=%\"%gg\"",
        "\"client-first\";bad=%\"%\"",
        "\"client-first\";bad=%oops",
        "\"client-first\";bad=%\"unterminated",
        "\t\"client-first\""};
    char selected[256];

    /* draft-ietf-webtrans-http3-16 Section 3.3: strings, client preference. */
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
        xqc_wt_interop_check(xqc_wt_interop_select_protocol(valid[i],
            strlen(valid[i]), protocols, 3, selected, sizeof(selected)) == 1
            && !strcmp(selected, "client-first"),
            "client preference selected and parameters ignored");
    }
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        xqc_wt_interop_check(xqc_wt_interop_select_protocol(invalid[i],
            strlen(invalid[i]), protocols, 3, selected, sizeof(selected))
                == -1, "malformed protocol list rejected");
    }
    const char escaped[] = "\"a\\\"b\\\\c\"";
    xqc_wt_interop_check(xqc_wt_interop_select_protocol(escaped,
        strlen(escaped), protocols, 3, selected, sizeof(selected)) == 1
        && !strcmp(selected, protocols[2]), "SF string escapes decoded");
    xqc_wt_interop_check(xqc_wt_interop_select_protocol("\"other\"", 7,
        protocols, 3, selected, sizeof(selected)) == 0,
        "no protocol intersection rejected");
    char long_protocol[1026], long_list[1028], long_selected[1025];
    memset(long_protocol, 'a', 1024);
    long_protocol[1024] = '\0';
    const char *long_offered[] = {long_protocol};
    snprintf(long_list, sizeof(long_list), "\"%s\"", long_protocol);
    xqc_wt_interop_check(xqc_wt_interop_select_protocol(long_list,
        strlen(long_list), long_offered, 1, long_selected,
        sizeof(long_selected)) == 1,
        "RFC 9651 required 1024-byte string accepted");
    long_protocol[1024] = 'a';
    long_protocol[1025] = '\0';
    snprintf(long_list, sizeof(long_list), "\"%s\"", long_protocol);
    xqc_wt_interop_check(xqc_wt_interop_select_protocol(long_list,
        strlen(long_list), long_offered, 1, long_selected,
        sizeof(long_selected)) == -1,
        "protocol over configured size bound rejected");
}

void
xqc_test_wt_interop_stream_ownership(void)
{
    unsigned char connection_data[64], before[64];
    int stream_marker, session_marker;
    xqc_wt_unistream_t *stream = (xqc_wt_unistream_t *) &stream_marker;
    xqc_wt_session_t *session = (xqc_wt_session_t *) &session_marker;

    memset(connection_data, 0xa5, sizeof(connection_data));
    memcpy(before, connection_data, sizeof(before));
    memset(&xqc_wt_interop, 0, sizeof(xqc_wt_interop));
    xqc_wt_interop_check(xqc_wt_interop_stream_create(stream, session,
        connection_data) == XQC_OK, "incoming stream with connection data");
    xqc_wt_interop_stream_t *state = xqc_wt_interop_find(stream);
    xqc_wt_interop_check(state && state->session == session
        && !state->sending && state->next == NULL,
        "incoming stream allocates owned callback state");
    xqc_wt_interop_check(!memcmp(connection_data, before, sizeof(before)),
        "incoming stream preserves inherited connection data");
    state->complete = 1;
    xqc_wt_interop_stream_close(stream, session, connection_data);
    xqc_wt_interop_check(xqc_wt_interop.streams == state && !state->stream,
        "closed state retained across synchronous callback unwinding");
    xqc_wt_interop_free_stream(state);

    state = xqc_wt_interop_allocate(session);
    xqc_wt_interop_check(state != NULL, "allocate outgoing stream state");
    state->sending = 1;
    xqc_wt_interop_check(xqc_wt_interop_stream_create(stream, session,
        state) == XQC_OK && xqc_wt_interop_find(stream) == state
        && state->next == NULL && state->sending,
        "outgoing stream reuses registered application state");
    xqc_wt_interop_free_stream(state);
}

void
xqc_test_wt_interop_stream_bound(void)
{
    int session_marker;
    xqc_wt_session_t *session = (xqc_wt_session_t *) &session_marker;

    memset(&xqc_wt_interop, 0, sizeof(xqc_wt_interop));
    for (size_t i = 0; i < XQC_WT_INTEROP_STREAMS_MAX; i++) {
        xqc_wt_interop_check(xqc_wt_interop_allocate(session) != NULL,
            "session accepts bounded GET and PUSH stream states");
    }
    xqc_wt_interop_check(xqc_wt_interop_allocate(session) == NULL
        && xqc_wt_interop.stream_count == XQC_WT_INTEROP_STREAMS_MAX,
        "reject stream beyond session memory bound");
    while (xqc_wt_interop.streams) {
        xqc_wt_interop_free_stream(xqc_wt_interop.streams);
    }
    xqc_wt_interop_check(xqc_wt_interop.stream_count == 0,
        "session cleanup releases every counted state");
    xqc_wt_interop_stream_t *state = xqc_wt_interop_allocate(session);
    xqc_wt_interop_check(state != NULL,
        "allocation available after previous session cleanup");
    xqc_wt_interop_free_stream(state);
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
