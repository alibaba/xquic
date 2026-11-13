/* Copyright (c) 2026, Alibaba Group Holding Limited. */
#include <CUnit/CUnit.h>
#include <string.h>
#include "xqc_moqt_interop_test.h"
#include "interop/moqt/fixture.h"

void
xqc_test_moqt_interop_fixture(void)
{
    xqc_moqt_namespace_t ns = {0};
    const char *fields[] = {"moq-test-00", "0", "0", "0", "2", "4",
        "5", "64", "32", "2", "1", "1", "0", "-1", "-1", "0"};
    for (size_t i = 0; i < 16; i++) {
        ns.fields[ns.count++] = (struct iovec){(void *)fields[i],
                                                strlen(fields[i])};
    }
    xqc_interop_fixture_t f;
    CU_ASSERT_EQUAL(xqc_interop_fixture_parse(&ns, &f), 0);
    CU_ASSERT_EQUAL(xqc_interop_fixture_count(&f), 15);
    CU_ASSERT_EQUAL(f.size0, 64);
    CU_ASSERT_EQUAL(f.mode, 0);
    CU_ASSERT_EQUAL(xqc_interop_fixture_case("moq-test-increments", &f), 0);
    CU_ASSERT_EQUAL(xqc_interop_fixture_count(&f), 9);
    CU_ASSERT_EQUAL(f.first_object, 3);
    CU_ASSERT_EQUAL(f.object_step, 2);

    xqc_interop_fixture_case("data-subgroup-basic", &f);
    xqc_moqt_location_t start = {1, 0}, end = {1, UINT64_MAX};
    unsigned first, last;
    CU_ASSERT_EQUAL(xqc_interop_history_window(&f, 13, &start, &end,
                                               &first, &last), 0);
    CU_ASSERT_EQUAL(first, 5);
    CU_ASSERT_EQUAL(last, 9);
    end = (xqc_moqt_location_t){2, 1};
    CU_ASSERT_EQUAL(xqc_interop_history_window(&f, 12, &start, &end,
                                               &first, &last), 0);
    CU_ASSERT_EQUAL(last, 11);

    xqc_interop_retention_t state = {.run = "run"};
    const char *names[] = {"moq-test",
        "publish-namespace-multi-publisher-retention", "run", "shared"};
    ns.count = 4;
    for (unsigned i = 0; i < 4; i++) {
        ns.fields[i] = (struct iovec){(void *)names[i], strlen(names[i])};
    }
    xqc_interop_retention_event(&state, &ns, 1);
    ns.fields[3] = (struct iovec){"sync", 4};
    xqc_interop_retention_event(&state, &ns, 1);
    xqc_interop_retention_event(&state, &ns, 0);
    CU_ASSERT_TRUE(state.present[0]);
    state.allow_remove = 1;
    ns.fields[3] = (struct iovec){"shared", 6};
    xqc_interop_retention_event(&state, &ns, 0);
    CU_ASSERT_FALSE(state.failed);
    CU_ASSERT_EQUAL(state.adds[0], 1);
    CU_ASSERT_EQUAL(state.removes[0], 1);
    CU_ASSERT_EQUAL(state.removes[1], 1);
}

void
xqc_test_moqt_interop_fixture_errors(void)
{
    xqc_interop_fixture_t f;
    xqc_moqt_namespace_t ns = {0};
    CU_ASSERT_NOT_EQUAL(xqc_interop_fixture_parse(&ns, &f), 0);
    CU_ASSERT_NOT_EQUAL(xqc_interop_fixture_case("unsupported", &f), 0);
    const char *fields[] = {"moq-test-00", "0", "0", "0", "2", "4",
        "5", "64", "32", "2", "0", "1", "0", "-1", "-1", "0"};
    for (size_t i = 0; i < 16; i++) {
        ns.fields[ns.count++] = (struct iovec){(void *)fields[i],
                                                strlen(fields[i])};
    }
    CU_ASSERT_NOT_EQUAL(xqc_interop_fixture_parse(&ns, &f), 0);
    ns.fields[10] = (struct iovec){"1", 1};
    ns.fields[7] = (struct iovec){"4096", 4};
    CU_ASSERT_NOT_EQUAL(xqc_interop_fixture_parse(&ns, &f), 0);
    ns.fields[7] = (struct iovec){"1x", 2};
    CU_ASSERT_NOT_EQUAL(xqc_interop_fixture_parse(&ns, &f), 0);

    xqc_interop_fixture_case("data-subgroup-basic", &f);
    xqc_moqt_location_t start = {2, 0}, end = {1, 4};
    unsigned first, last;
    CU_ASSERT_NOT_EQUAL(xqc_interop_history_window(&f, 15, &start, &end,
                                                   &first, &last), 0);
    end.group_id = 2;
    CU_ASSERT_NOT_EQUAL(xqc_interop_history_window(&f, 0, &start, &end,
                                                   &first, &last), 0);
    CU_ASSERT_NOT_EQUAL(xqc_interop_history_window(&f, 16, &start, &end,
                                                   &first, &last), 0);
    start.object_id = 5;
    CU_ASSERT_NOT_EQUAL(xqc_interop_history_window(&f, 15, &start, &end,
                                                   &first, &last), 0);

    xqc_interop_retention_t state = {.run = "run"};
    const char *names[] = {"moq-test",
        "publish-namespace-multi-publisher-retention", "run", "shared"};
    ns.count = 4;
    for (unsigned i = 0; i < 4; i++) {
        ns.fields[i] = (struct iovec){(void *)names[i], strlen(names[i])};
    }
    xqc_interop_retention_event(&state, &ns, 1);
    xqc_interop_retention_event(&state, &ns, 0);
    CU_ASSERT_TRUE(state.failed); /* Withdrawal before the last publisher. */
    state = (xqc_interop_retention_t){.run = "run"};
    ns.fields[2] = (struct iovec){"another-run", 11};
    xqc_interop_retention_event(&state, &ns, 1);
    CU_ASSERT_TRUE(state.failed);
}

void
xqc_test_moqt_interop_oracle(void)
{
    xqc_interop_oracle_t oracle = {0};
    xqc_interop_fixture_case("data-subgroup-basic", &oracle.fixture);
    char bytes[64];
    memset(bytes, 't', sizeof(bytes));
    /* Out-of-order Groups are legal; completeness uses identity, not count. */
    for (int g = 2; g >= 0; g--) {
        for (unsigned id = 0; id < 5; id++) {
            unsigned size = id == 0 ? 64 : 32;
            xqc_moqt_object_t o = {.group_id = g, .object_id = id,
                .priority = 128, .payload_length = size,
                .payload = {bytes, size / 2}};
            xqc_interop_oracle_object(&oracle, &o);
            o.payload_offset = size / 2;
            xqc_interop_oracle_object(&oracle, &o);
        }
    }
    CU_ASSERT_TRUE(xqc_interop_oracle_complete(&oracle, 0));
    CU_ASSERT_EQUAL(oracle.objects, 15);
    CU_ASSERT_FALSE(xqc_interop_oracle_complete(&oracle, 1));
    xqc_moqt_location_t start = {0, 0}, end = {2, 4};
    CU_ASSERT_TRUE(xqc_interop_history_complete(&oracle, &start, &end));
    start.group_id = 1;
    CU_ASSERT_FALSE(xqc_interop_history_complete(&oracle, &start, &end));
    for (unsigned i = 0; i < 5; i++) {
        oracle.seen[i] = 0;
    }
    oracle.objects -= 5;
    CU_ASSERT_TRUE(xqc_interop_history_complete(&oracle, &start, &end));
    oracle.seen[14] = 0;
    oracle.objects--;
    end.object_id = 3;
    CU_ASSERT_TRUE(xqc_interop_history_complete(&oracle, &start, &end));
}

void
xqc_test_moqt_interop_oracle_errors(void)
{
    xqc_interop_oracle_t oracle = {0};
    xqc_interop_fixture_case("data-subgroup-basic", &oracle.fixture);
    CU_ASSERT_FALSE(xqc_interop_oracle_complete(&oracle, 0));
    xqc_moqt_location_t start = {0, 0}, end = {2, 4};
    CU_ASSERT_FALSE(xqc_interop_history_complete(&oracle, &start, &end));
    CU_ASSERT_TRUE(xqc_interop_oracle_complete(&oracle, 1));
    char bytes[64];
    memset(bytes, 't', sizeof(bytes));
    xqc_moqt_object_t o = {.priority = 128, .payload_length = 64,
                            .payload = {bytes, 64}};
    xqc_interop_oracle_object(&oracle, &o);
    xqc_interop_oracle_object(&oracle, &o);
    CU_ASSERT_TRUE(oracle.failed);
    CU_ASSERT_FALSE(xqc_interop_history_complete(&oracle, &start, &end));
    memset(oracle.seen, 0, sizeof(oracle.seen));
    memset(oracle.offsets, 0, sizeof(oracle.offsets));
    oracle.failed = 0;
    bytes[0] = 'x';
    xqc_interop_oracle_object(&oracle, &o);
    CU_ASSERT_TRUE(oracle.failed);
    oracle.failed = 0;
    o.group_id = 100;
    xqc_interop_oracle_object(&oracle, &o);
    CU_ASSERT_TRUE(oracle.failed);
}

void
xqc_test_moqt_interop_properties(void)
{
    xqc_interop_oracle_t oracle = {.origin = 1};
    xqc_interop_fixture_case("moq-test-extensions", &oracle.fixture);
    char bytes[64];
    memset(bytes, 't', sizeof(bytes));
    unsigned char props[] = {2, 42, 3, 3, 'a', 'b', 'c'};
    xqc_moqt_object_t object = {.priority = 200, .payload_length = 64,
        .payload = {bytes, 64}, .properties = {props, sizeof(props)}};
    xqc_interop_oracle_object(&oracle, &object);
    CU_ASSERT_FALSE(oracle.failed);
    CU_ASSERT_EQUAL(oracle.objects, 1);
    oracle = (xqc_interop_oracle_t){0};
    xqc_interop_fixture_case("moq-test-extensions", &oracle.fixture);
    unsigned char fixed[] = {2, 1, 3, 1, 'x'};
    object.properties = (struct iovec){fixed, sizeof(fixed)};
    xqc_interop_oracle_object(&oracle, &object);
    CU_ASSERT_FALSE(oracle.failed);
    CU_ASSERT_EQUAL(oracle.objects, 1);
}

void
xqc_test_moqt_interop_properties_errors(void)
{
    for (unsigned i = 0; i < 4; i++) {
        xqc_interop_oracle_t oracle = {.origin = i != 3};
        xqc_interop_fixture_case("moq-test-extensions", &oracle.fixture);
        char bytes[64];
        memset(bytes, 't', sizeof(bytes));
        unsigned char props[] = {2, 42, i == 0 ? 5 : 3, 3, 'a', 'b', 'c'};
        xqc_moqt_object_t object = {.priority = 200, .payload_length = 64,
            .payload = {bytes, 64},
            .properties = {props, i == 1 ? sizeof(props) - 1
                                    : i == 2 ? 1 : sizeof(props)}};
        xqc_interop_oracle_object(&oracle, &object);
        CU_ASSERT_TRUE(oracle.failed);
    }
}
