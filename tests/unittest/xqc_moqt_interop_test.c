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
}

void
xqc_test_moqt_interop_oracle_errors(void)
{
    xqc_interop_oracle_t oracle = {0};
    xqc_interop_fixture_case("data-subgroup-basic", &oracle.fixture);
    CU_ASSERT_FALSE(xqc_interop_oracle_complete(&oracle, 0));
    CU_ASSERT_TRUE(xqc_interop_oracle_complete(&oracle, 1));
    char bytes[64];
    memset(bytes, 't', sizeof(bytes));
    xqc_moqt_object_t o = {.priority = 128, .payload_length = 64,
                            .payload = {bytes, 64}};
    xqc_interop_oracle_object(&oracle, &o);
    xqc_interop_oracle_object(&oracle, &o);
    CU_ASSERT_TRUE(oracle.failed);
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
