/* Copyright (c) 2026, Alibaba Group Holding Limited. */
#include <CUnit/CUnit.h>
#include <string.h>
#include "xqc_moqt_interop_test.h"
#include "interop/moqt/fixture.h"
#include "interop/moqt/media.h"

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
    ns.fields[13] = (struct iovec){"1", 1};
    ns.fields[14] = (struct iovec){"-1", 2};
    CU_ASSERT_EQUAL(xqc_interop_fixture_parse(&ns, &f), 0);
    CU_ASSERT_EQUAL(f.extensions, 1);
    ns.fields[13] = (struct iovec){"-1", 2};
    ns.fields[14] = (struct iovec){"2", 1};
    CU_ASSERT_EQUAL(xqc_interop_fixture_parse(&ns, &f), 0);
    CU_ASSERT_EQUAL(f.extensions, 2);
    CU_ASSERT_EQUAL(xqc_interop_fixture_case(
        "moq-test-object-fragmentation", &f), 0);
    CU_ASSERT_EQUAL(f.mode, 4);
    CU_ASSERT_EQUAL(f.size0, 96);
    CU_ASSERT_EQUAL(xqc_interop_fixture_count(&f), 1);
    CU_ASSERT_EQUAL(xqc_interop_fixture_case(
        "moq-test-object-large-id", &f), 0);
    CU_ASSERT_EQUAL(f.first_group, UINT64_C(1) << 40);
    CU_ASSERT_EQUAL(f.first_object, (UINT64_C(1) << 40) + 5);
    CU_ASSERT_EQUAL(xqc_interop_fixture_count(&f), 6);
    CU_ASSERT_EQUAL(xqc_interop_fixture_case("subscribe-cancel-live", &f), 0);
    CU_ASSERT_EQUAL(xqc_interop_fixture_count(&f), 18);
    CU_ASSERT_EQUAL(f.pace_ms, 20);
    f.first_group = 0;
    f.last_group = UINT64_MAX;
    f.first_object = 0;
    f.last_object = UINT64_MAX;
    f.group_step = 1;
    f.object_step = 1;
    CU_ASSERT_EQUAL(xqc_interop_fixture_count(&f), 0);
    ns.fields[13] = (struct iovec){"1", 1};
    ns.fields[14] = (struct iovec){"2", 1};
    CU_ASSERT_EQUAL(xqc_interop_fixture_parse(&ns, &f), 0);
    CU_ASSERT_EQUAL(f.extensions, 3);
    CU_ASSERT_EQUAL(xqc_interop_fixture_case("moq-test-increments", &f), 0);
    CU_ASSERT_EQUAL(xqc_interop_fixture_count(&f), 9);
    CU_ASSERT_EQUAL(f.first_object, 3);
    CU_ASSERT_EQUAL(f.object_step, 2);
    CU_ASSERT_EQUAL(xqc_interop_fixture_case(
        "moq-test-extensions-integer-only", &f), 0);
    CU_ASSERT_EQUAL(f.extensions, 1);
    CU_ASSERT_EQUAL(xqc_interop_fixture_case(
        "moq-test-extensions-variable-only", &f), 0);
    CU_ASSERT_EQUAL(f.extensions, 2);
    CU_ASSERT_EQUAL(xqc_interop_fixture_case(
        "moq-test-subgroup-per-group-no-eog", &f), 0);
    CU_ASSERT_EQUAL(f.mode, 0);
    CU_ASSERT_EQUAL(f.markers, 0);
    CU_ASSERT_EQUAL(xqc_interop_fixture_count(&f), 18);
    CU_ASSERT_EQUAL(xqc_interop_fixture_case(
        "moq-test-subgroup-per-group-nonzero-start", &f), 0);
    CU_ASSERT_EQUAL(f.mode, 0);
    CU_ASSERT_EQUAL(f.first_group, 6);
    CU_ASSERT_EQUAL(f.last_group, 8);
    CU_ASSERT_EQUAL(f.first_object, 3);
    CU_ASSERT_EQUAL(f.last_object, 5);
    CU_ASSERT_EQUAL(xqc_interop_fixture_count(&f), 9);
    CU_ASSERT_EQUAL(xqc_interop_fixture_case(
        "moq-test-datagram-sparse-ids", &f), 0);
    CU_ASSERT_EQUAL(f.mode, 3);
    CU_ASSERT_EQUAL(f.first_group, 10);
    CU_ASSERT_EQUAL(f.last_group, 24);
    CU_ASSERT_EQUAL(f.first_object, 3);
    CU_ASSERT_EQUAL(f.last_object, 7);
    CU_ASSERT_EQUAL(f.group_step, 7);
    CU_ASSERT_EQUAL(f.object_step, 2);
    CU_ASSERT_EQUAL(xqc_interop_fixture_count(&f), 9);
    CU_ASSERT_EQUAL(xqc_interop_fixture_case(
        "moq-test-subgroup-per-object-sparse-ids", &f), 0);
    CU_ASSERT_EQUAL(f.mode, 1);
    CU_ASSERT_EQUAL(f.first_group, 4);
    CU_ASSERT_EQUAL(f.first_object, 2);
    CU_ASSERT_EQUAL(f.last_object, 8);
    CU_ASSERT_EQUAL(f.object_step, 3);
    CU_ASSERT_EQUAL(f.markers, 0);
    CU_ASSERT_EQUAL(xqc_interop_fixture_count(&f), 3);
    CU_ASSERT_EQUAL(xqc_interop_fixture_case(
        "moq-test-two-subgroups-no-eog", &f), 0);
    CU_ASSERT_EQUAL(f.mode, 2);
    CU_ASSERT_EQUAL(f.objects_per_group, 6);
    CU_ASSERT_EQUAL(f.markers, 0);
    CU_ASSERT_EQUAL(xqc_interop_fixture_count(&f), 21);
    CU_ASSERT_EQUAL(xqc_interop_fixture_case(
        "moq-test-datagram-nonzero-start", &f), 0);
    CU_ASSERT_EQUAL(f.mode, 3);
    CU_ASSERT_EQUAL(f.first_group, 6);
    CU_ASSERT_EQUAL(f.first_object, 3);
    CU_ASSERT_EQUAL(f.last_group, 8);
    CU_ASSERT_EQUAL(f.last_object, 5);
    CU_ASSERT_EQUAL(xqc_interop_fixture_count(&f), 9);

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
    start = (xqc_moqt_location_t){0, 5};
    end = (xqc_moqt_location_t){0, UINT64_MAX};
    CU_ASSERT_EQUAL(xqc_interop_history_window(&f, 11, &start, &end,
                                               &first, &last), 0);
    CU_ASSERT_TRUE(first > last);
    xqc_interop_oracle_t empty = {.fixture = f};
    CU_ASSERT_TRUE(xqc_interop_history_complete(&empty, &start, &end));
    empty.objects = 1;
    CU_ASSERT_FALSE(xqc_interop_history_complete(&empty, &start, &end));

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
    ns.fields[13] = (struct iovec){"3", 1};
    CU_ASSERT_NOT_EQUAL(xqc_interop_fixture_parse(&ns, &f), 0);
    ns.fields[13] = (struct iovec){"-1", 2};
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
    start = (xqc_moqt_location_t){2, 5};
    end = (xqc_moqt_location_t){2, UINT64_MAX};
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

    /* Draft-22 Sections 5.1.1 and 5.1.3 allow relay priorities in FETCH. */
    oracle = (xqc_interop_oracle_t){.fixture = oracle.fixture};
    xqc_moqt_object_t historical = {.priority = 0, .payload_length = 64,
                                    .payload = {bytes, sizeof(bytes)}};
    xqc_interop_oracle_object(&oracle, &historical);
    CU_ASSERT_TRUE(oracle.failed);
    CU_ASSERT_EQUAL(oracle.objects, 0);

    oracle = (xqc_interop_oracle_t){
        .fixture = oracle.fixture, .ignore_priority = 1,
    };
    start = end = (xqc_moqt_location_t){0, 0};
    xqc_interop_oracle_object(&oracle, &historical);
    CU_ASSERT_TRUE(xqc_interop_history_complete(&oracle, &start, &end));

    historical.object_id = 1;
    historical.payload_length = historical.payload.iov_len = 32;
    bytes[0] = 'x';
    xqc_interop_oracle_object(&oracle, &historical);
    end.object_id = 1;
    CU_ASSERT_FALSE(xqc_interop_history_complete(&oracle, &start, &end));
}

void
xqc_test_moqt_interop_fragmentation(void)
{
    xqc_interop_oracle_t oracle = {0};
    CU_ASSERT_EQUAL(xqc_interop_fixture_case(
        "moq-test-object-fragmentation", &oracle.fixture), 0);
    unsigned char bytes[96];
    memset(bytes, 't', sizeof(bytes));
    xqc_moqt_object_t object = {.priority = 200, .payload_length = 96};
    for (size_t offset = 0; offset < sizeof(bytes); offset += 24) {
        object.payload_offset = offset;
        object.payload = (struct iovec){bytes + offset, 24};
        xqc_interop_oracle_object(&oracle, &object);
        if (offset + 24 < sizeof(bytes)) {
            CU_ASSERT_FALSE(xqc_interop_oracle_complete(&oracle, 0));
        }
    }
    CU_ASSERT_TRUE(xqc_interop_oracle_complete(&oracle, 0));
    CU_ASSERT_EQUAL(oracle.objects, 1);
}

void
xqc_test_moqt_interop_fragmentation_errors(void)
{
    xqc_interop_oracle_t oracle = {0};
    xqc_interop_fixture_case("moq-test-object-fragmentation",
                             &oracle.fixture);
    unsigned char bytes[96];
    memset(bytes, 't', sizeof(bytes));
    xqc_moqt_object_t object = {.priority = 200, .payload_length = 96};
    object.payload = (struct iovec){bytes, 24};
    xqc_interop_oracle_object(&oracle, &object);
    object.payload_offset = 24;
    object.payload = (struct iovec){bytes + 24, 24};
    xqc_interop_oracle_object(&oracle, &object);
    object.payload_offset = 48;
    object.payload = (struct iovec){bytes + 48, 24};
    xqc_interop_oracle_object(&oracle, &object);
    CU_ASSERT_FALSE(xqc_interop_oracle_complete(&oracle, 0));

    oracle = (xqc_interop_oracle_t){0};
    xqc_interop_fixture_case("moq-test-object-fragmentation",
                             &oracle.fixture);
    object = (xqc_moqt_object_t){.priority = 200, .payload_length = 96,
        .payload_offset = 24, .payload = {bytes + 24, 24}};
    xqc_interop_oracle_object(&oracle, &object);
    CU_ASSERT_TRUE(oracle.failed);
    CU_ASSERT_FALSE(xqc_interop_oracle_complete(&oracle, 0));
}

void
xqc_test_moqt_interop_large_id(void)
{
    xqc_interop_oracle_t oracle = {0};
    CU_ASSERT_EQUAL(xqc_interop_fixture_case(
        "moq-test-object-large-id", &oracle.fixture), 0);
    const char *tuple[] = {"moq-test-00", "0", "1099511627776",
        "1099511627781", "1099511627777", "1099511627785", "5",
        "64", "32", "2", "1", "2", "0", "-1", "-1", "0"};
    xqc_moqt_namespace_t ns = {0};
    for (unsigned i = 0; i < 16; i++) {
        ns.fields[ns.count++] = (struct iovec){(void *)tuple[i],
                                               strlen(tuple[i])};
    }
    xqc_interop_fixture_t parsed;
    CU_ASSERT_EQUAL(xqc_interop_fixture_parse(&ns, &parsed), 0);
    CU_ASSERT_EQUAL(parsed.first_group, UINT64_C(1) << 40);
    CU_ASSERT_EQUAL(parsed.last_object, (UINT64_C(1) << 40) + 9);

    unsigned char bytes[64];
    memset(bytes, 't', sizeof(bytes));
    const xqc_interop_fixture_t *f = &oracle.fixture;
    for (uint64_t group = f->first_group; group <= f->last_group; group++) {
        for (uint64_t id = f->first_object; id <= f->last_object;
             id += f->object_step)
        {
            unsigned size = id == f->first_object ? f->size0 : f->size;
            xqc_moqt_object_t object = {.group_id = group,
                .object_id = id, .priority = 200 + group % 2,
                .payload = {bytes, size}, .payload_length = size};
            xqc_interop_oracle_object(&oracle, &object);
        }
    }
    CU_ASSERT_TRUE(xqc_interop_oracle_complete(&oracle, 0));
    CU_ASSERT_EQUAL(oracle.objects, 6);
}

void
xqc_test_moqt_interop_large_id_errors(void)
{
    xqc_interop_oracle_t oracle = {0};
    xqc_interop_fixture_case("moq-test-object-large-id", &oracle.fixture);
    xqc_moqt_object_t object = {.group_id = oracle.fixture.first_group,
        .object_id = oracle.fixture.first_object - 1, .priority = 200};
    xqc_interop_oracle_object(&oracle, &object);
    CU_ASSERT_TRUE(oracle.failed);
    CU_ASSERT_FALSE(xqc_interop_oracle_complete(&oracle, 0));
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

    const char *cases[] = {"moq-test-extensions-integer-only",
                           "moq-test-extensions-variable-only"};
    unsigned char integer[] = {2, 1};
    unsigned char variable[] = {5, 1, 'x'};
    unsigned char variable_random[] = {5, 3, 'a', 'b', 'c'};
    for (unsigned i = 0; i < 2; i++) {
        oracle = (xqc_interop_oracle_t){0};
        CU_ASSERT_EQUAL(xqc_interop_fixture_case(cases[i], &oracle.fixture), 0);
        object.properties = i == 0
            ? (struct iovec){integer, sizeof(integer)}
            : (struct iovec){variable, sizeof(variable)};
        xqc_interop_oracle_object(&oracle, &object);
        CU_ASSERT_FALSE(oracle.failed);
        CU_ASSERT_EQUAL(oracle.objects, 1);

        oracle = (xqc_interop_oracle_t){.origin = 1};
        CU_ASSERT_EQUAL(xqc_interop_fixture_case(cases[i], &oracle.fixture), 0);
        object.properties = i == 0
            ? (struct iovec){props, 2}
            : (struct iovec){variable_random, sizeof(variable_random)};
        xqc_interop_oracle_object(&oracle, &object);
        CU_ASSERT_FALSE(oracle.failed);
        CU_ASSERT_EQUAL(oracle.objects, 1);
    }
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

    const char *cases[] = {"moq-test-extensions-integer-only",
                           "moq-test-extensions-variable-only"};
    unsigned char integer[] = {2, 1};
    unsigned char variable[] = {5, 1, 'x'};
    for (unsigned i = 0; i < 2; i++) {
        xqc_interop_oracle_t oracle = {.origin = 1};
        xqc_interop_fixture_case(cases[i], &oracle.fixture);
        char bytes[64];
        memset(bytes, 't', sizeof(bytes));
        xqc_moqt_object_t object = {.priority = 200, .payload_length = 64,
            .payload = {bytes, 64},
            .properties = i == 0
                ? (struct iovec){variable, sizeof(variable)}
                : (struct iovec){integer, sizeof(integer)}};
        xqc_interop_oracle_object(&oracle, &object);
        CU_ASSERT_TRUE(oracle.failed);
    }
}

void
xqc_test_moqt_interop_catalog(void)
{
    uint8_t bytes[1024];
    int n = xqc_interop_media_catalog(bytes, sizeof(bytes));
    CU_ASSERT(n > 0);
    xqc_interop_media_t m = {.kind = XQC_INTEROP_MEDIA_CATALOG};
    xqc_moqt_object_t object = {.priority = 128, .payload_length = n,
        .payload = {bytes, n / 2}};
    xqc_interop_media_receive(&m, &object);
    CU_ASSERT_EQUAL(m.count, 0);
    object.payload_offset = n / 2;
    object.payload = (struct iovec){bytes + n / 2, n - n / 2};
    xqc_interop_media_receive(&m, &object);
    CU_ASSERT_EQUAL(m.count, 1);
    CU_ASSERT_EQUAL(m.error, 0);
    char name[32];
    CU_ASSERT_EQUAL(xqc_interop_media_track(&m, name, sizeof(name)), 0);
    CU_ASSERT_STRING_EQUAL(name, "video");
}

void
xqc_test_moqt_interop_catalog_errors(void)
{
    char name[32];
    xqc_interop_media_t m = {.kind = XQC_INTEROP_MEDIA_CATALOG};
    CU_ASSERT_NOT_EQUAL(xqc_interop_media_track(&m, name, sizeof(name)), 0);
    const char *invalid[] = {
        "{\"msfVersion\":\"draft-99\",\"tracks\":[]}",
        "{\"msfVersion\":\"draft-01\",\"tracks\":[]}",
        "{\"msfVersion\":\"draft-01\",\"tracks\":[{\"name\":\"video\","
        "\"isLive\":true,\"packaging\":\"cmaf\"}]}",
        "{\"msfVersion\":\"draft-01\",\"tracks\":["
    };
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        m = (xqc_interop_media_t){.kind = XQC_INTEROP_MEDIA_CATALOG};
        xqc_moqt_object_t object = {.priority = 128,
            .payload = {(void *)invalid[i], strlen(invalid[i])},
            .payload_length = strlen(invalid[i])};
        xqc_interop_media_receive(&m, &object);
        CU_ASSERT_NOT_EQUAL(xqc_interop_media_track(&m, name, sizeof(name)), 0);
    }
    uint8_t bytes[1024];
    int n = xqc_interop_media_catalog(bytes, sizeof(bytes));
    /* MSF-01 5: independent catalog is Object 0 of Subgroup 0. */
    for (unsigned i = 0; i < 3; i++) {
        m = (xqc_interop_media_t){.kind = XQC_INTEROP_MEDIA_CATALOG};
        xqc_moqt_object_t object = {.priority = 128, .payload_length = n,
            .payload = {bytes, n}, .object_id = i == 0,
            .subgroup_id = i == 1, .group_id = i == 2};
        xqc_interop_media_receive(&m, &object);
        CU_ASSERT_NOT_EQUAL(m.error, 0);
    }
}

void
xqc_test_moqt_interop_media(void)
{
    xqc_interop_media_t m = {.kind = XQC_INTEROP_MEDIA_VIDEO};
    /* Independent streams can deliver Groups out of order. */
    for (int i = XQC_INTEROP_MEDIA_FRAMES - 1; i >= 0; i--) {
        uint8_t properties[32];
        xqc_moqt_object_t object;
        CU_ASSERT_EQUAL(xqc_interop_media_sample(i, &object,
                            properties, sizeof(properties)), 0);
        size_t n = object.payload.iov_len / 2;
        object.payload.iov_len = n;
        xqc_interop_media_receive(&m, &object);
        CU_ASSERT_EQUAL(m.count, XQC_INTEROP_MEDIA_FRAMES - 1 - i);
        object.payload_offset = n;
        object.payload.iov_base = (uint8_t *)object.payload.iov_base + n;
        object.payload.iov_len = object.payload_length - n;
        object.properties = (struct iovec){0};
        xqc_interop_media_receive(&m, &object);
        CU_ASSERT_EQUAL(m.error, 0);
    }
    CU_ASSERT_EQUAL(m.count, XQC_INTEROP_MEDIA_FRAMES);
}

void
xqc_test_moqt_interop_media_errors(void)
{
    for (unsigned i = 0; i < 10; i++) {
        xqc_interop_media_t m = {.kind = XQC_INTEROP_MEDIA_VIDEO};
        uint8_t properties[32], bad[1024];
        xqc_moqt_object_t object;
        CU_ASSERT_EQUAL(xqc_interop_media_sample(0, &object,
                            properties, sizeof(properties)), 0);
        switch (i) {
        case 0: object.object_id = 1; break;
        case 1: object.group_id = XQC_INTEROP_MEDIA_FRAMES; break;
        case 2: object.payload_offset = 1; break;
        case 3: object.properties.iov_len--; break;
        case 4:
            properties[0] = 8;
            properties[1] = 0;
            object.properties.iov_len = 2;
            break;
        case 5: object.datagram = 1; break;
        case 6:
            memcpy(bad, object.payload.iov_base, object.payload.iov_len);
            bad[0] ^= 1;
            object.payload.iov_base = bad;
            break;
        case 7:
            xqc_interop_media_receive(&m, &object);
            break;
        case 8: object.payload.iov_len = object.payload_length + 1; break;
        case 9: object.payload.iov_base = NULL; break;
        }
        xqc_interop_media_receive(&m, &object);
        CU_ASSERT_NOT_EQUAL(m.error, 0);
        CU_ASSERT_NOT_EQUAL(xqc_interop_media_render(&m), 0);
    }
    xqc_interop_media_t m = {.kind = XQC_INTEROP_MEDIA_VIDEO};
    CU_ASSERT_NOT_EQUAL(xqc_interop_media_render(&m), 0);
    xqc_moqt_object_t object;
    uint8_t properties[32];
    CU_ASSERT_NOT_EQUAL(xqc_interop_media_sample(XQC_INTEROP_MEDIA_FRAMES,
                            &object, properties, sizeof(properties)), 0);
}
