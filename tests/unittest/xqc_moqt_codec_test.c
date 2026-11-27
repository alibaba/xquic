/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_moqt_codec_test.h"
#include "moq/moqt/xqc_moqt_codec.h"
#include "src/common/xqc_str.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"

/* Draft-22 section 9: frame boundaries only, not typed message bodies. */
void
xqc_test_moqt_frames(void)
{
    const uint8_t wire[] = {0xaf, 0x00, 0x00, 0x03, 0x00, 0xff, 0x7f};
    xqc_moqt_message_t msg = {XQC_MOQT_MSG_SETUP,
                             {(void *)(wire + 4), 3}};
    xqc_moqt_message_t decoded = {0};
    uint8_t buf[32] = {0};
    CU_ASSERT_EQUAL(xqc_moqt_frame_encode(&msg, NULL, 0), sizeof(wire));
    CU_ASSERT_EQUAL(xqc_moqt_frame_encode(&msg, buf, sizeof(buf)),
                    sizeof(wire));
    CU_ASSERT_EQUAL(xqc_memcmp(buf, wire, sizeof(wire)), 0);
    CU_ASSERT_EQUAL(xqc_moqt_frame_decode(wire, sizeof(wire), &decoded),
                    sizeof(wire));
    CU_ASSERT_EQUAL(decoded.type, XQC_MOQT_MSG_SETUP);
    CU_ASSERT_PTR_EQUAL(decoded.body.iov_base, wire + 4);
    CU_ASSERT_EQUAL(decoded.body.iov_len, 3);
    msg.body.iov_base = buf + 4;
    CU_ASSERT_EQUAL(xqc_moqt_frame_encode(&msg, buf, sizeof(buf)),
                    sizeof(wire));
    CU_ASSERT_EQUAL(xqc_memcmp(buf, wire, sizeof(wire)), 0);

    const uint8_t types[] = {2, 3, 4, 5, 6, 7, 8, 11, 13, 14, 15, 16,
                             22, 24, 29, 34, 80, 81};
    for (size_t i = 0; i < sizeof(types); i++) {
        msg.type = types[i];
        msg.body.iov_base = NULL;
        msg.body.iov_len = 0;
        CU_ASSERT_EQUAL(xqc_moqt_frame_encode(&msg, buf, sizeof(buf)), 3);
        CU_ASSERT_EQUAL(buf[0], types[i]);
        CU_ASSERT_EQUAL(buf[1], 0);
        CU_ASSERT_EQUAL(buf[2], 0);
        CU_ASSERT_EQUAL(xqc_moqt_frame_decode(buf, 3, &decoded), 3);
        CU_ASSERT_EQUAL(decoded.type, types[i]);
    }

    /* Non-minimal Type, followed by a second frame in the same buffer. */
    const uint8_t joined[] = {0x80, 0x10, 0x00, 0x00, 0x07, 0x00, 0x00};
    CU_ASSERT_EQUAL(xqc_moqt_frame_decode(joined, sizeof(joined), &decoded), 4);
    CU_ASSERT_EQUAL(decoded.type, XQC_MOQT_MSG_GOAWAY);
    CU_ASSERT_EQUAL(xqc_moqt_frame_decode(joined + 4, 3, &decoded), 3);
    CU_ASSERT_EQUAL(decoded.type, XQC_MOQT_MSG_REQUEST_OK);

    static uint8_t payload[65535], large[65539];
    msg.type = XQC_MOQT_MSG_SETUP;
    msg.body.iov_base = payload;
    msg.body.iov_len = sizeof(payload);
    CU_ASSERT_EQUAL(xqc_moqt_frame_encode(&msg, large, sizeof(large)),
                    sizeof(large));
    CU_ASSERT_EQUAL(large[2], 0xff);
    CU_ASSERT_EQUAL(large[3], 0xff);
    CU_ASSERT_EQUAL(xqc_moqt_frame_decode(large, sizeof(large), &decoded),
                    sizeof(large));
    CU_ASSERT_EQUAL(decoded.body.iov_len, sizeof(payload));
}

void
xqc_test_moqt_frame_errors(void)
{
    const uint8_t wire[] = {0xaf, 0x00, 0x00, 0x03, 0x00, 0xff, 0x7f};
    xqc_moqt_message_t msg = {XQC_MOQT_MSG_SETUP,
                             {(void *)(wire + 4), 3}};
    xqc_moqt_message_t before = {UINT64_MAX, {NULL, SIZE_MAX}};
    xqc_moqt_message_t decoded = before;
    uint8_t buf[16], unchanged[sizeof(buf)];
    xqc_memset(buf, 0xa5, sizeof(buf));
    xqc_memcpy(unchanged, buf, sizeof(buf));
    for (size_t n = 0; n < sizeof(wire); n++) {
        CU_ASSERT_EQUAL(xqc_moqt_frame_encode(&msg, buf, n), -XQC_ENOBUF);
        CU_ASSERT_EQUAL(xqc_memcmp(buf, unchanged, sizeof(buf)), 0);
        CU_ASSERT_EQUAL(xqc_moqt_frame_decode(wire, n, &decoded), -XQC_EAGAIN);
        CU_ASSERT_EQUAL(xqc_memcmp(&decoded, &before, sizeof(before)), 0);
    }
    CU_ASSERT_EQUAL(xqc_moqt_frame_decode(wire, sizeof(wire), &decoded),
                    sizeof(wire));
    const uint8_t reserved[] = {0, 1, 0x20, 0x21, 0x40, 0x41, 0x1e, 0x7f};
    for (size_t i = 0; i < sizeof(reserved); i++) {
        decoded = before;
        CU_ASSERT_EQUAL(xqc_moqt_frame_decode(reserved + i, 1, &decoded),
                        -XQC_EILLEGAL_FRAME);
        CU_ASSERT_EQUAL(xqc_memcmp(&decoded, &before, sizeof(before)), 0);
        msg.type = reserved[i];
        CU_ASSERT_EQUAL(xqc_moqt_frame_encode(&msg, buf, sizeof(buf)),
                        -XQC_EPARAM);
        CU_ASSERT_EQUAL(xqc_memcmp(buf, unchanged, sizeof(buf)), 0);
    }
    msg.type = XQC_MOQT_MSG_SETUP;
    msg.body.iov_len = 65536;
    CU_ASSERT_EQUAL(xqc_moqt_frame_encode(&msg, NULL, 0), -XQC_EPARAM);
    msg.body.iov_len = 1;
    msg.body.iov_base = NULL;
    CU_ASSERT_EQUAL(xqc_moqt_frame_encode(&msg, buf, sizeof(buf)), -XQC_EPARAM);
    msg.body.iov_len = 0;
    CU_ASSERT_EQUAL(xqc_moqt_frame_encode(&msg, NULL, 1), -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_moqt_frame_encode(NULL, buf, sizeof(buf)), -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_moqt_frame_decode(NULL, 0, &decoded), -XQC_EAGAIN);
    CU_ASSERT_EQUAL(xqc_moqt_frame_decode(NULL, 1, &decoded), -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_moqt_frame_decode(wire, sizeof(wire), NULL),
                    -XQC_EPARAM);
}

/* Sections 2.4.1-2 and 8.7: binary fields and complete-tuple matching. */
void
xqc_test_moqt_names(void)
{
    const uint8_t wire[] = {2, 3, 'a', 0, 'b', 2, 0xff, 'c', 0};
    xqc_moqt_namespace_t ns = {2, {{(void *)(wire + 2), 3},
                                   {(void *)(wire + 6), 2}}};
    struct iovec name = {NULL, 0}, decoded_name;
    xqc_moqt_namespace_t decoded;
    uint8_t buf[64];
    CU_ASSERT_EQUAL(xqc_moqt_name_encode(&ns, &name, NULL, 0), sizeof(wire));
    CU_ASSERT_EQUAL(xqc_moqt_name_encode(&ns, &name, buf, sizeof(buf)),
                    sizeof(wire));
    CU_ASSERT_EQUAL(xqc_memcmp(buf, wire, sizeof(wire)), 0);
    CU_ASSERT_EQUAL(xqc_moqt_name_decode(wire, sizeof(wire), &decoded,
                                         &decoded_name), sizeof(wire));
    CU_ASSERT_EQUAL(decoded.count, 2);
    CU_ASSERT_EQUAL(decoded.fields[0].iov_len, 3);
    CU_ASSERT_PTR_EQUAL(decoded.fields[0].iov_base, wire + 2);
    CU_ASSERT_EQUAL(decoded_name.iov_len, 0);
    CU_ASSERT(xqc_moqt_namespace_prefix(&ns, &decoded));
    ns.count = 1;
    CU_ASSERT(xqc_moqt_namespace_prefix(&ns, &decoded));
    CU_ASSERT_FALSE(xqc_moqt_namespace_prefix(&decoded, &ns));
    CU_ASSERT_EQUAL(xqc_moqt_name_encode(&ns, NULL, buf, sizeof(buf)), 5);
    CU_ASSERT_EQUAL(xqc_moqt_name_decode(buf, 5, &decoded, NULL), 5);
    ns.fields[0].iov_len = 2;
    CU_ASSERT_FALSE(xqc_moqt_namespace_prefix(&ns, &decoded));
    ns.fields[0].iov_len = 3;
    ns.fields[0].iov_base = (void *)"a\0c";
    CU_ASSERT_FALSE(xqc_moqt_namespace_prefix(&ns, &decoded));
    ns.count = 0;
    CU_ASSERT(xqc_moqt_namespace_prefix(&ns, &decoded));
    CU_ASSERT_EQUAL(xqc_moqt_name_encode(&ns, NULL, buf, sizeof(buf)), 1);
    CU_ASSERT_EQUAL(buf[0], 0);
    CU_ASSERT_EQUAL(xqc_moqt_name_decode(buf, 1, &decoded, NULL), 1);
    CU_ASSERT_EQUAL(decoded.count, 0);

    xqc_moqt_namespace_t a = {2, {{(void *)"a", 1}, {(void *)"bc", 2}}};
    xqc_moqt_namespace_t b = {2, {{(void *)"ab", 2}, {(void *)"c", 1}}};
    CU_ASSERT_FALSE(xqc_moqt_namespace_prefix(&a, &b));
    const uint8_t nonminimal[] = {0x80, 1, 0x80, 1, 'x', 0x80, 0};
    CU_ASSERT_EQUAL(xqc_moqt_name_decode(nonminimal, sizeof(nonminimal),
                                         &decoded, &decoded_name),
                    sizeof(nonminimal));
    CU_ASSERT_EQUAL(decoded.count, 1);
    CU_ASSERT_EQUAL(decoded.fields[0].iov_len, 1);

    static uint8_t payload[4096], large[4400];
    ns.count = 32;
    for (size_t i = 0; i < ns.count; i++) {
        ns.fields[i].iov_base = payload;
        ns.fields[i].iov_len = 128;
    }
    xqc_int_t n = xqc_moqt_name_encode(&ns, NULL, large, sizeof(large));
    CU_ASSERT_EQUAL(n, 4161);
    CU_ASSERT_EQUAL(xqc_moqt_name_decode(large, n, &decoded, NULL), n);
    CU_ASSERT_EQUAL(decoded.count, 32);
    ns.count = 0;
    name.iov_base = payload;
    name.iov_len = sizeof(payload);
    n = xqc_moqt_name_encode(&ns, &name, large, sizeof(large));
    CU_ASSERT_EQUAL(n, 4099);
    CU_ASSERT_EQUAL(xqc_moqt_name_decode(large, n, &decoded, &decoded_name), n);
    CU_ASSERT_EQUAL(decoded_name.iov_len, sizeof(payload));
}

void
xqc_test_moqt_name_errors(void)
{
    const uint8_t wire[] = {2, 3, 'a', 0, 'b', 2, 0xff, 'c', 1, 't'};
    xqc_moqt_namespace_t ns = {2, {{(void *)(wire + 2), 3},
                                   {(void *)(wire + 6), 2}}};
    struct iovec name = {(void *)(wire + 9), 1};
    xqc_moqt_namespace_t before = {0}, decoded;
    struct iovec name_before = {NULL, SIZE_MAX}, decoded_name;
    uint8_t buf[32], unchanged[sizeof(buf)];
    xqc_memset(buf, 0xa5, sizeof(buf));
    xqc_memcpy(unchanged, buf, sizeof(buf));
    for (size_t n = 0; n < sizeof(wire); n++) {
        decoded = before;
        decoded_name = name_before;
        CU_ASSERT_EQUAL(xqc_moqt_name_encode(&ns, &name, buf, n), -XQC_ENOBUF);
        CU_ASSERT_EQUAL(xqc_memcmp(buf, unchanged, sizeof(buf)), 0);
        CU_ASSERT_EQUAL(xqc_moqt_name_decode(wire, n, &decoded, &decoded_name),
                        -XQC_EAGAIN);
        CU_ASSERT_EQUAL(xqc_memcmp(&decoded, &before, sizeof(before)), 0);
        CU_ASSERT_EQUAL(decoded_name.iov_len, SIZE_MAX);
        CU_ASSERT_PTR_NULL(decoded_name.iov_base);
    }
    CU_ASSERT_EQUAL(xqc_moqt_name_decode(wire, sizeof(wire), &decoded,
                                         &decoded_name), sizeof(wire));
    const uint8_t invalid[][4] = {{33}, {1, 0}, {1, 0x90, 0x01},
                                  {0, 0x90, 0x01}, {1, 0xff}};
    const size_t sizes[] = {1, 2, 3, 3, 2};
    for (size_t i = 0; i < 4; i++) {
        decoded = before;
        CU_ASSERT_EQUAL(xqc_moqt_name_decode(invalid[i], sizes[i], &decoded,
                                             &decoded_name),
                        -XQC_EILLEGAL_FRAME);
        CU_ASSERT_EQUAL(xqc_memcmp(&decoded, &before, sizeof(before)), 0);
    }
    CU_ASSERT_EQUAL(xqc_moqt_name_decode(invalid[4], sizes[4], &decoded, NULL),
                    -XQC_EAGAIN);
    const uint8_t short_count[] = {0xff};
    CU_ASSERT_EQUAL(xqc_moqt_name_decode(short_count, 1, &decoded, NULL),
                    -XQC_EAGAIN);

    /* A valid namespace exhausts the full-name budget before track bytes. */
    static uint8_t full_name[4101] = {1, 0x90, 0};
    full_name[4099] = 1;
    full_name[4100] = 't';
    CU_ASSERT_EQUAL(xqc_moqt_name_decode(full_name, sizeof(full_name),
                                         &decoded, &decoded_name),
                    -XQC_EILLEGAL_FRAME);
    /* The same aggregate bound applies across namespace fields. */
    full_name[0] = 2;
    CU_ASSERT_EQUAL(xqc_moqt_name_decode(full_name, sizeof(full_name),
                                         &decoded, NULL),
                    -XQC_EILLEGAL_FRAME);

    ns.count = 33;
    CU_ASSERT_EQUAL(xqc_moqt_name_encode(&ns, &name, buf, sizeof(buf)),
                    -XQC_EPARAM);
    ns.count = 1;
    ns.fields[0].iov_len = 0;
    CU_ASSERT_EQUAL(xqc_moqt_name_encode(&ns, NULL, buf, sizeof(buf)),
                    -XQC_EPARAM);
    ns.fields[0].iov_len = 1;
    ns.fields[0].iov_base = NULL;
    CU_ASSERT_EQUAL(xqc_moqt_name_encode(&ns, NULL, buf, sizeof(buf)),
                    -XQC_EPARAM);
    ns.fields[0].iov_base = buf;
    ns.fields[0].iov_len = SIZE_MAX;
    CU_ASSERT_EQUAL(xqc_moqt_name_encode(&ns, NULL, NULL, 0), -XQC_EPARAM);
    ns.fields[0].iov_len = 4096;
    CU_ASSERT_EQUAL(xqc_moqt_name_encode(&ns, &name, NULL, 0), -XQC_EPARAM);
    ns.count = 0;
    name.iov_base = NULL;
    CU_ASSERT_EQUAL(xqc_moqt_name_encode(&ns, &name, NULL, 0), -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_moqt_name_encode(&ns, NULL, NULL, 1), -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_moqt_name_encode(NULL, NULL, NULL, 0), -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_moqt_name_decode(NULL, 0, &decoded, NULL), -XQC_EAGAIN);
    CU_ASSERT_EQUAL(xqc_moqt_name_decode(NULL, 1, &decoded, NULL), -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_moqt_name_decode(wire, sizeof(wire), NULL, NULL),
                    -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_memcmp(buf, unchanged, sizeof(buf)), 0);
}

/* Section 8.3: parity is based on the resulting Type, not its delta. */
void
xqc_test_moqt_kv(void)
{
    const uint8_t wire[] = {2, 0xbb, 0xbd, 1, 3, 'a', 0, 'b', 1, 0xff,
                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    xqc_moqt_kv_t kv = {2, {.integer = 15293}}, decoded;
    uint8_t buf[32];
    CU_ASSERT_EQUAL(xqc_moqt_kv_encode(&kv, 0, NULL, 0), 3);
    CU_ASSERT_EQUAL(xqc_moqt_kv_encode(&kv, 0, buf, sizeof(buf)), 3);
    CU_ASSERT_EQUAL(xqc_memcmp(buf, wire, 3), 0);
    CU_ASSERT_EQUAL(xqc_moqt_kv_decode(wire, sizeof(wire), 0, &decoded), 3);
    CU_ASSERT_EQUAL(decoded.type, 2);
    CU_ASSERT_EQUAL(decoded.value.integer, 15293);
    kv.type = 3;
    kv.value.bytes.iov_base = (void *)(wire + 5);
    kv.value.bytes.iov_len = 3;
    CU_ASSERT_EQUAL(xqc_moqt_kv_encode(&kv, 2, buf, sizeof(buf)), 5);
    CU_ASSERT_EQUAL(xqc_memcmp(buf, wire + 3, 5), 0);
    CU_ASSERT_EQUAL(xqc_moqt_kv_decode(wire + 3, sizeof(wire) - 3, 2,
                                       &decoded), 5);
    CU_ASSERT_EQUAL(decoded.type, 3);
    CU_ASSERT_EQUAL(decoded.value.bytes.iov_len, 3);
    CU_ASSERT_PTR_EQUAL(decoded.value.bytes.iov_base, wire + 5);
    CU_ASSERT_EQUAL(xqc_moqt_kv_decode(wire + 8, sizeof(wire) - 8, 3,
                                       &decoded), 10);
    CU_ASSERT_EQUAL(decoded.type, 4);
    CU_ASSERT_EQUAL(decoded.value.integer, UINT64_MAX);
    CU_ASSERT_EQUAL(xqc_moqt_kv_encode(&decoded, 3, buf, sizeof(buf)), 10);
    CU_ASSERT_EQUAL(xqc_memcmp(buf, wire + 8, 10), 0);

    /* Zero delta is valid here; duplicate policy belongs to the caller. */
    const uint8_t empty[] = {0, 0};
    kv.type = UINT64_MAX;
    kv.value.bytes.iov_base = NULL;
    kv.value.bytes.iov_len = 0;
    CU_ASSERT_EQUAL(xqc_moqt_kv_encode(&kv, UINT64_MAX, buf, sizeof(buf)),
                    2);
    CU_ASSERT_EQUAL(xqc_memcmp(buf, empty, 2), 0);
    CU_ASSERT_EQUAL(xqc_moqt_kv_decode(empty, 2, UINT64_MAX, &decoded), 2);
    CU_ASSERT_EQUAL(decoded.type, UINT64_MAX);
    CU_ASSERT_EQUAL(decoded.value.bytes.iov_len, 0);
    const uint8_t nonminimal[] = {0x80, 1, 0x80, 0};
    CU_ASSERT_EQUAL(xqc_moqt_kv_decode(nonminimal, sizeof(nonminimal), 0,
                                       &decoded), sizeof(nonminimal));
    CU_ASSERT_EQUAL(decoded.type, 1);

    static uint8_t payload[65535], large[65539];
    kv.type = 1;
    kv.value.bytes.iov_base = payload;
    kv.value.bytes.iov_len = sizeof(payload);
    CU_ASSERT_EQUAL(xqc_moqt_kv_encode(&kv, 0, large, sizeof(large)),
                    sizeof(large));
    CU_ASSERT_EQUAL(xqc_moqt_kv_decode(large, sizeof(large), 0, &decoded),
                    sizeof(large));
    CU_ASSERT_EQUAL(decoded.value.bytes.iov_len, sizeof(payload));
}

void
xqc_test_moqt_kv_errors(void)
{
    const uint8_t wire[] = {1, 3, 'a', 0, 'b'};
    xqc_moqt_kv_t kv = {1, {.bytes = {(void *)(wire + 2), 3}}};
    xqc_moqt_kv_t before = {UINT64_MAX, {.integer = UINT64_MAX}}, decoded;
    uint8_t buf[16], unchanged[sizeof(buf)];
    xqc_memset(buf, 0xa5, sizeof(buf));
    xqc_memcpy(unchanged, buf, sizeof(buf));
    for (size_t n = 0; n < sizeof(wire); n++) {
        decoded = before;
        CU_ASSERT_EQUAL(xqc_moqt_kv_encode(&kv, 0, buf, n), -XQC_ENOBUF);
        CU_ASSERT_EQUAL(xqc_memcmp(buf, unchanged, sizeof(buf)), 0);
        CU_ASSERT_EQUAL(xqc_moqt_kv_decode(wire, n, 0, &decoded), -XQC_EAGAIN);
        CU_ASSERT_EQUAL(xqc_memcmp(&decoded, &before, sizeof(before)), 0);
    }
    CU_ASSERT_EQUAL(xqc_moqt_kv_decode(wire, sizeof(wire), 0, &decoded),
                    sizeof(wire));
    const uint8_t short_delta[] = {0xff};
    CU_ASSERT_EQUAL(xqc_moqt_kv_decode(short_delta, 1, 0, &decoded),
                    -XQC_EAGAIN);
    const uint8_t oversized[] = {1, 0xc1, 0, 0};
    CU_ASSERT_EQUAL(xqc_moqt_kv_decode(oversized, sizeof(oversized), 0,
                                       &decoded),
                    -XQC_EILLEGAL_FRAME);
    decoded = before;
    CU_ASSERT_EQUAL(xqc_moqt_kv_decode(wire, sizeof(wire), UINT64_MAX,
                                       &decoded), -XQC_EILLEGAL_FRAME);
    CU_ASSERT_EQUAL(xqc_memcmp(&decoded, &before, sizeof(before)), 0);
    CU_ASSERT_EQUAL(xqc_moqt_kv_encode(&kv, 2, buf, sizeof(buf)), -XQC_EPARAM);
    kv.value.bytes.iov_len = 65536;
    CU_ASSERT_EQUAL(xqc_moqt_kv_encode(&kv, 0, buf, sizeof(buf)), -XQC_EPARAM);
    kv.value.bytes.iov_len = 1;
    kv.value.bytes.iov_base = NULL;
    CU_ASSERT_EQUAL(xqc_moqt_kv_encode(&kv, 0, buf, sizeof(buf)), -XQC_EPARAM);
    kv.value.bytes.iov_len = 0;
    CU_ASSERT_EQUAL(xqc_moqt_kv_encode(&kv, 0, NULL, 1), -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_moqt_kv_encode(NULL, 0, NULL, 0), -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_moqt_kv_decode(NULL, 0, 0, &decoded), -XQC_EAGAIN);
    CU_ASSERT_EQUAL(xqc_moqt_kv_decode(NULL, 1, 0, &decoded), -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_moqt_kv_decode(wire, sizeof(wire), 0, NULL),
                    -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_memcmp(buf, unchanged, sizeof(buf)), 0);
}

void
xqc_test_moqt_datagram_codec(void)
{
    /* Draft-22 11.2.1: independently assemble every legal flags combination. */
    const uint8_t statuses[] = {0, 3, 4};
    for (uint8_t flags = 0; flags <= 0x2f; flags++) {
        if ((flags & 0x10) || ((flags & 0x20) && (flags & 2))) {
            continue;
        }
        for (size_t j = 0; j < sizeof(statuses); j++) {
            if ((!(flags & 0x20) && j) || ((flags & 1) && j)) {
                continue;
            }
            uint8_t wire[32] = {0x80, flags, 1, 2};
            size_t len = 4;
            if (!(flags & 4)) {
                wire[len++] = 3;
            }
            if (!(flags & 8)) {
                wire[len++] = 7;
            }
            if (flags & 1) {
                wire[len++] = 2;
                wire[len++] = 0x78;
                wire[len++] = 9;
            }
            wire[len++] = flags & 0x20 ? statuses[j] : 'x';
            uint64_t alias = UINT64_MAX, decoded_flags = UINT64_MAX;
            xqc_moqt_object_t o;
            CU_ASSERT_EQUAL(xqc_moqt_datagram_decode(wire, len, &alias,
                                                     &decoded_flags, &o), len);
            CU_ASSERT_EQUAL(alias, 1);
            CU_ASSERT_EQUAL(decoded_flags, flags);
            CU_ASSERT_EQUAL(o.group_id, 2);
            CU_ASSERT_EQUAL(o.object_id, flags & 4 ? 0 : 3);
            CU_ASSERT_EQUAL(o.priority, flags & 8 ? 0 : 7);
            CU_ASSERT_EQUAL(o.end_of_group, !!(flags & 2));
            CU_ASSERT_EQUAL(o.properties.iov_len, flags & 1 ? 2 : 0);
            CU_ASSERT_EQUAL(o.status, flags & 0x20 ? statuses[j] : 0);
            CU_ASSERT_EQUAL(o.payload.iov_len, flags & 0x20 ? 0 : 1);
            CU_ASSERT_EQUAL(o.payload_length, o.payload.iov_len);
            CU_ASSERT_EQUAL(o.payload_offset, 0);
            CU_ASSERT_TRUE(o.datagram);
            uint8_t encoded[32];
            xqc_int_t n = xqc_moqt_datagram_encode(alias, &o, NULL, 0);
            CU_ASSERT(n > 0);
            CU_ASSERT_EQUAL(xqc_moqt_datagram_encode(alias, &o, encoded,
                                                     sizeof(encoded)), n);
            xqc_moqt_object_t roundtrip;
            CU_ASSERT_EQUAL(xqc_moqt_datagram_decode(
                encoded, n, &alias,
                &decoded_flags, &roundtrip), n);
            CU_ASSERT_EQUAL(roundtrip.object_id, o.object_id);
            CU_ASSERT_EQUAL(roundtrip.status, o.status);
            CU_ASSERT_EQUAL(roundtrip.end_of_group, o.end_of_group);
            CU_ASSERT_EQUAL(roundtrip.properties.iov_len, o.properties.iov_len);
            CU_ASSERT_EQUAL(roundtrip.payload.iov_len, o.payload.iov_len);
        }
    }
    /* Normal status equals an empty payload; EOG cannot use STATUS. */
    xqc_moqt_object_t o = {.datagram = 1, .end_of_group = 1};
    uint8_t wire[64];
    xqc_int_t n = xqc_moqt_datagram_encode(UINT64_MAX, &o, wire, sizeof(wire));
    uint64_t alias, flags;
    CU_ASSERT_EQUAL(xqc_moqt_datagram_decode(wire, n, &alias, &flags, &o), n);
    CU_ASSERT_EQUAL(alias, UINT64_MAX);
    CU_ASSERT_EQUAL(o.payload.iov_len, 0);
    CU_ASSERT_EQUAL(o.status, XQC_MOQT_OBJECT_NORMAL);
    CU_ASSERT_TRUE(o.end_of_group);
    const uint8_t padding[] = {0xf0, 0x13, 0x2b, 0x3e, 0x29, 0xff};
    CU_ASSERT_EQUAL(xqc_moqt_datagram_decode(padding, sizeof(padding), &alias,
                                             &flags, &o), sizeof(padding));
    CU_ASSERT_EQUAL(flags, XQC_MOQT_PADDING_DATAGRAM);
}

void
xqc_test_moqt_datagram_codec_errors(void)
{
    const uint8_t complete[] = {0x21, 1, 2, 3, 4, 2, 0x78, 9, 0};
    uint64_t alias = 99, flags = 99;
    xqc_moqt_object_t o, before;
    xqc_memset(&before, 0xa5, sizeof(before));
    for (size_t len = 0; len < sizeof(complete); len++) {
        o = before;
        CU_ASSERT_EQUAL(xqc_moqt_datagram_decode(
            complete, len, &alias,
            &flags, &o), -XQC_EILLEGAL_FRAME);
        CU_ASSERT_EQUAL(alias, 99);
        CU_ASSERT_EQUAL(flags, 99);
        CU_ASSERT_EQUAL(xqc_memcmp(&o, &before, sizeof(o)), 0);
    }
    const struct {
        uint8_t     wire[10];
        size_t      len;
    } bad[] = {
        {{0xff}, 1}, {{0x10}, 1}, {{0x40}, 1}, {{0x22}, 1},
        {{0, 1, 2}, 3}, {{0, 1, 2, 3}, 4},
        {{1, 1, 2, 3, 4, 0}, 6}, {{1, 1, 2, 3, 4, 3, 0}, 7},
        {{0x20, 1, 2, 3, 4, 1}, 6}, {{0x20, 1, 2, 3, 4, 0, 0}, 7},
        {{0x21, 1, 2, 3, 4, 2, 0x78, 9, 3}, 9},
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        CU_ASSERT_EQUAL(xqc_moqt_datagram_decode(
            bad[i].wire, bad[i].len,
            &alias, &flags, &o), -XQC_EILLEGAL_FRAME);
    }
    CU_ASSERT_EQUAL(xqc_moqt_datagram_decode(NULL, 1, &alias, &flags, &o),
                    -XQC_EILLEGAL_FRAME);
    CU_ASSERT_EQUAL(xqc_moqt_datagram_decode(complete, SIZE_MAX, &alias,
                                             &flags, &o), -XQC_EILLEGAL_FRAME);
    CU_ASSERT_EQUAL(xqc_moqt_datagram_decode(complete, 1, NULL, &flags, &o),
                    -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_moqt_datagram_decode(complete, 1, &alias, NULL, &o),
                    -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_moqt_datagram_decode(complete, 1, &alias, &flags, NULL),
                    -XQC_EPARAM);
    xqc_memzero(&o, sizeof(o));
    o.datagram = 1;
    o.payload = (struct iovec){"abc", 3};
    o.payload_length = 3;
    uint8_t buf[32], unchanged[sizeof(buf)];
    xqc_memset(buf, 0xa5, sizeof(buf));
    xqc_memcpy(unchanged, buf, sizeof(buf));
    xqc_int_t n = xqc_moqt_datagram_encode(1, &o, NULL, 0);
    for (xqc_int_t cap = 0; cap < n; cap++) {
        CU_ASSERT_EQUAL(xqc_moqt_datagram_encode(1, &o, buf, cap), -XQC_ENOBUF);
        CU_ASSERT_EQUAL(xqc_memcmp(buf, unchanged, sizeof(buf)), 0);
    }
    xqc_moqt_object_t good = o;
    for (unsigned i = 0; i < 11; i++) {
        o = good;
        switch (i) {
        case 0:
            o.datagram = 0;
            break;
        case 1:
            o.payload_offset = 1;
            break;
        case 2:
            o.payload_length--;
            break;
        case 3:
            o.payload.iov_base = NULL;
            break;
        case 4:
            o.properties.iov_len = 1;
            break;
        case 5:
            o.properties = (struct iovec){buf, SIZE_MAX};
            break;
        case 6:
            o.status = 2;
            break;
        case 7:
            o.status = XQC_MOQT_OBJECT_END_GROUP;
            break;
        case 8:
            o.payload.iov_len = o.payload_length = 0;
            o.status = XQC_MOQT_OBJECT_END_TRACK;
            o.end_of_group = 1;
            break;
        case 9:
            o.payload.iov_len = o.payload_length = 0;
            o.status = XQC_MOQT_OBJECT_END_GROUP;
            o.properties = (struct iovec){buf, 1};
            break;
        default:
            break;
        }
        CU_ASSERT_EQUAL(xqc_moqt_datagram_encode(1, &o, i == 10 ? NULL : buf,
                                                 sizeof(buf)), -XQC_EPARAM);
    }
    o = good;
    o.payload.iov_len = o.payload_length = SIZE_MAX;
    CU_ASSERT_EQUAL(xqc_moqt_datagram_encode(1, &o, NULL, 0), -XQC_ELIMIT);
    CU_ASSERT_EQUAL(xqc_moqt_datagram_encode(1, NULL, NULL, 0), -XQC_EPARAM);
}

void
xqc_test_moqt_subgroup_codec(void)
{
    /* Draft-22 11.3.1: independent vectors for all three ID modes/flags. */
    for (uint8_t flags = 0x10; flags <= 0x7f; flags++) {
        if (!(flags & 0x10) || (flags & 6) == 6) {
            continue;
        }
        uint8_t wire[64] = {0x80, flags, 1, 2};
        size_t len = 4;
        if (flags & 4) {
            wire[len++] = 3;
        }
        if (!(flags & 0x20)) {
            wire[len++] = 7;
        }
        xqc_moqt_object_t o;
        uint64_t alias, decoded_flags;
        for (size_t cut = 0; cut < len; cut++) {
            CU_ASSERT_EQUAL(xqc_moqt_subgroup_header_decode(
                wire, cut,
                &alias, &decoded_flags, &o), -XQC_EAGAIN);
        }
        CU_ASSERT_EQUAL(xqc_moqt_subgroup_header_decode(
            wire, len,
            &alias, &decoded_flags, &o), len);
        CU_ASSERT_EQUAL(alias, 1);
        CU_ASSERT_EQUAL(decoded_flags, flags);
        CU_ASSERT_EQUAL(o.group_id, 2);
        CU_ASSERT_EQUAL(o.subgroup_id, (flags & 4) ? 3 : 0);
        CU_ASSERT_EQUAL(o.priority, (flags & 0x20) ? 0 : 7);
        uint8_t encoded[64];
        xqc_int_t n = xqc_moqt_subgroup_header_encode(alias, flags, &o,
                                                      NULL, 0);
        CU_ASSERT_EQUAL(n, len - 1);
        xqc_memset(encoded, 0xcc, sizeof(encoded));
        CU_ASSERT_EQUAL(xqc_moqt_subgroup_header_encode(
            alias, flags, &o,
            encoded, n - 1), -XQC_ENOBUF);
        CU_ASSERT_EQUAL(encoded[0], 0xcc);
        CU_ASSERT_EQUAL(xqc_moqt_subgroup_header_encode(
            alias, flags, &o,
            encoded, sizeof(encoded)), n);
        CU_ASSERT_EQUAL(encoded[0], flags);
        CU_ASSERT_EQUAL(xqc_memcmp(encoded + 1, wire + 2, len - 2), 0);

        const uint8_t body[] = {5, 0, 1, 'x'};
        const uint8_t *p = (flags & 1) ? body : body + 1;
        uint8_t object_wire[4];
        xqc_memcpy(object_wire, p, (flags & 1) ? 4 : 3);
        object_wire[0] = 5;
        size_t header = (flags & 1) ? 3 : 2;
        for (size_t cut = 0; cut < header; cut++) {
            CU_ASSERT_EQUAL(xqc_moqt_object_header_decode(
                object_wire, cut,
                flags, NULL, &o), -XQC_EAGAIN);
        }
        CU_ASSERT_EQUAL(xqc_moqt_object_header_decode(object_wire, header,
                                                      flags, NULL, &o), header);
        CU_ASSERT_EQUAL(o.object_id, 5);
        CU_ASSERT_EQUAL(o.payload_length, 1);
        CU_ASSERT_EQUAL(o.subgroup_id, (flags & 4) ? 3 : (flags & 2) ? 5 : 0);
        CU_ASSERT_EQUAL(o.first_in_subgroup, !!(flags & 0x40));
        CU_ASSERT_EQUAL(xqc_moqt_object_header_encode(
            flags, NULL, &o,
            encoded, sizeof(encoded)), header);
        CU_ASSERT_EQUAL(xqc_memcmp(encoded, object_wire, header), 0);
        CU_ASSERT_EQUAL(xqc_moqt_object_header_encode(flags, NULL, &o,
                                                      NULL, 0), header);
        encoded[0] = 0xcc;
        CU_ASSERT_EQUAL(xqc_moqt_object_header_encode(
            flags, NULL, &o,
            encoded, header - 1), -XQC_ENOBUF);
        CU_ASSERT_EQUAL(encoded[0], 0xcc);
        xqc_moqt_object_t previous = o;
        object_wire[0] = 0;
        CU_ASSERT_EQUAL(xqc_moqt_object_header_decode(
            object_wire, header,
            flags, &previous, &o), header);
        CU_ASSERT_EQUAL(o.object_id, 6);
        CU_ASSERT_FALSE(o.first_in_subgroup);
        CU_ASSERT_EQUAL(xqc_moqt_object_header_encode(
            flags, &previous, &o,
            encoded, sizeof(encoded)), header);
        CU_ASSERT_EQUAL(encoded[0], 0);
    }
}

void
xqc_test_moqt_subgroup_codec_errors(void)
{
    uint8_t wire[] = {0x16, 1, 2, 3, 7};
    xqc_moqt_object_t o;
    uint64_t alias = 99, flags = 99;
    CU_ASSERT_EQUAL(xqc_moqt_subgroup_header_decode(
        wire, sizeof(wire),
        &alias, &flags, &o), -XQC_EILLEGAL_FRAME);
    CU_ASSERT_EQUAL(alias, 99);
    wire[0] = 0;
    CU_ASSERT_EQUAL(xqc_moqt_subgroup_header_decode(
        wire, sizeof(wire),
        &alias, &flags, &o), -XQC_EILLEGAL_FRAME);
    const uint8_t statuses[] = {0, 1, 2, 3, 4, 5};
    for (size_t i = 0; i < sizeof(statuses); i++) {
        xqc_memzero(&o, sizeof(o));
        uint8_t body[] = {0, 0, statuses[i]};
        xqc_int_t valid = statuses[i] == 0 || statuses[i] == 3
                          || statuses[i] == 4;
        CU_ASSERT_EQUAL(xqc_moqt_object_header_decode(
            body, sizeof(body),
            0x10, NULL, &o), valid ? sizeof(body) : -XQC_EILLEGAL_FRAME);
        if (valid) {
            uint8_t encoded[8];
            CU_ASSERT_EQUAL(xqc_moqt_object_header_encode(
                0x10, NULL, &o,
                encoded, sizeof(encoded)), sizeof(body));
            CU_ASSERT_EQUAL(xqc_memcmp(body, encoded, sizeof(body)), 0);
        }
    }
    xqc_memzero(&o, sizeof(o));
    xqc_moqt_object_t previous = {.object_id = UINT64_MAX};
    const uint8_t empty[] = {0, 0, 0};
    CU_ASSERT_EQUAL(xqc_moqt_object_header_decode(
        empty, sizeof(empty),
        0x10, &previous, &o), -XQC_EILLEGAL_FRAME);
    CU_ASSERT_EQUAL(xqc_moqt_object_header_encode(0x10, &previous, &o,
                                                  NULL, 0), -XQC_EPARAM);
    const uint8_t properties[] = {0, 1, 0, 0, 3};
    CU_ASSERT_EQUAL(xqc_moqt_object_header_decode(
        properties,
        sizeof(properties), 0x11, NULL, &o), -XQC_EILLEGAL_FRAME);
    o.status = XQC_MOQT_OBJECT_END_GROUP;
    o.payload_length = 1;
    CU_ASSERT_EQUAL(xqc_moqt_object_header_encode(0x10, NULL, &o, NULL, 0),
                    -XQC_EPARAM);
}

void
xqc_test_moqt_fetch_codec(void)
{
    /* Draft-22 11.4.1.1: every flag combination, with independent histories. */
    for (unsigned order = XQC_MOQT_GROUP_ASCENDING;
         order <= XQC_MOQT_GROUP_DESCENDING; order++)
    {
        for (uint64_t flags = 0; flags < XQC_MOQT_FETCH_RANGE_MIN; flags++) {
            xqc_moqt_fetch_history_t previous = {.location = {100, 5},
                .subgroup_id = 7, .priority = 9, .has_location = 1,
                .has_subgroup = 1, .has_priority = 1};
            uint8_t wire[128], *p = wire, *end = wire + sizeof(wire);
            p += xqc_vi64_write(p, end, flags);
            if (flags & XQC_MOQT_FETCH_GROUP) {
                p += xqc_vi64_write(p, end, 1);
            }
            if (!(flags & XQC_MOQT_FETCH_DATAGRAM)
                && (flags & XQC_MOQT_FETCH_SUBGROUP_MASK)
                   == XQC_MOQT_FETCH_SUBGROUP_EXPLICIT)
            {
                p += xqc_vi64_write(p, end, 12);
            }
            if (flags & XQC_MOQT_FETCH_OBJECT) {
                p += xqc_vi64_write(p, end, 3);
            }
            if (flags & XQC_MOQT_FETCH_PRIORITY) {
                *p++ = 17;
            }
            if (flags & XQC_MOQT_FETCH_PROPERTIES) {
                *p++ = 2;
                *p++ = 0;
                *p++ = 9;
            }
            *p++ = 0; /* Empty Normal has no Object Status field. */
            size_t len = p - wire;
            xqc_moqt_object_t o;
            for (size_t i = 0; i < len; i++) {
                xqc_moqt_fetch_history_t h = previous;
                CU_ASSERT_EQUAL(xqc_moqt_fetch_header_decode(wire, i, order,
                                                              &h, &o),
                                -XQC_EAGAIN);
                CU_ASSERT_EQUAL(h.location.object_id, 5);
            }
            xqc_moqt_fetch_history_t h = previous;
            CU_ASSERT_EQUAL(xqc_moqt_fetch_header_decode(wire, len, order,
                                                          &h, &o), len);
            CU_ASSERT_EQUAL(o.group_id, (flags & XQC_MOQT_FETCH_GROUP)
                ? (order == XQC_MOQT_GROUP_ASCENDING ? 102 : 98) : 100);
            CU_ASSERT_EQUAL(o.object_id, (flags & XQC_MOQT_FETCH_OBJECT)
                ? (flags & XQC_MOQT_FETCH_GROUP ? 3 : 8) : 6);
            CU_ASSERT_EQUAL(o.priority, flags & XQC_MOQT_FETCH_PRIORITY
                ? 17 : 9);
            CU_ASSERT_EQUAL(o.datagram, !!(flags & XQC_MOQT_FETCH_DATAGRAM));
            if (!o.datagram) {
                const uint64_t subgroups[] = {0, 7, 8, 12};
                CU_ASSERT_EQUAL(o.subgroup_id, subgroups[flags & 3]);
            }
            uint8_t encoded[128];
            xqc_int_t n = xqc_moqt_fetch_header_encode(order, &previous, &o,
                                                        NULL, 0);
            CU_ASSERT(n > 0);
            CU_ASSERT_EQUAL(xqc_moqt_fetch_header_encode(order, &previous, &o,
                encoded, n - 1), -XQC_ENOBUF);
            CU_ASSERT_EQUAL(xqc_moqt_fetch_header_encode(order, &previous, &o,
                encoded, sizeof(encoded)), n);
            h = previous;
            xqc_moqt_object_t decoded;
            CU_ASSERT_EQUAL(xqc_moqt_fetch_header_decode(encoded, n, order,
                &h, &decoded), n);
            CU_ASSERT_EQUAL(decoded.object_id, o.object_id);
            CU_ASSERT_EQUAL(decoded.subgroup_id, o.subgroup_id);
        }
    }
    for (unsigned range = XQC_MOQT_RANGE_NONEXISTENT;
         range <= XQC_MOQT_RANGE_TIMEOUT; range++)
    {
        xqc_moqt_fetch_history_t h = {.location = {100, 5},
            .has_location = 1, .has_subgroup = 1, .subgroup_id = 7,
            .has_priority = 1, .priority = 9};
        xqc_moqt_object_t o = {.group_id = 100, .object_id = 8, .range = range};
        uint8_t wire[32];
        xqc_int_t n = xqc_moqt_fetch_header_encode(XQC_MOQT_GROUP_ASCENDING,
            &h, &o, wire, sizeof(wire));
        CU_ASSERT(n > 0);
        for (size_t i = 0; i < n; i++) {
            CU_ASSERT_EQUAL(xqc_moqt_fetch_header_decode(wire, i,
                XQC_MOQT_GROUP_ASCENDING, &h, &o), -XQC_EAGAIN);
        }
        CU_ASSERT_EQUAL(xqc_moqt_fetch_header_decode(wire, n,
            XQC_MOQT_GROUP_ASCENDING, &h, &o), n);
        CU_ASSERT_EQUAL(o.range, range);
        CU_ASSERT_EQUAL(h.subgroup_id, 7);
        CU_ASSERT_EQUAL(h.priority, 9);
        /* Range changes G/O only: omitted S/P refer to last actual Object. */
        const uint8_t next[] = {1, 0};
        CU_ASSERT_EQUAL(xqc_moqt_fetch_header_decode(next, sizeof(next),
            XQC_MOQT_GROUP_ASCENDING, &h, &o), sizeof(next));
        CU_ASSERT_EQUAL(o.object_id, 9);
        CU_ASSERT_EQUAL(o.subgroup_id, 7);
        CU_ASSERT_EQUAL(o.priority, 9);
    }
    /* First absolute Object, then mixed Subgroups in ascending Object order. */
    const uint8_t objects[][6] = {{0x1f, 100, 0, 5, 7, 0},
        {0x02, 0}, {0x04, 3, 0}, {0x0f, 1, 7, 0, 0}};
    const size_t lengths[] = {6, 2, 3, 5};
    const uint64_t ids[] = {5, 6, 9, 0}, groups[] = {100, 100, 100, 102};
    xqc_moqt_fetch_history_t h;
    xqc_memzero(&h, sizeof(h));
    xqc_moqt_object_t o;
    /* Use the canonical writer for the initial absolute record. */
    xqc_moqt_object_t first = {.group_id = 100, .object_id = 5, .priority = 7};
    uint8_t wire[32];
    xqc_int_t n = xqc_moqt_fetch_header_encode(XQC_MOQT_GROUP_ASCENDING,
        &h, &first, wire, sizeof(wire));
    for (size_t i = 0; i < 4; i++) {
        CU_ASSERT(xqc_moqt_fetch_header_decode(i ? objects[i] : wire,
            i ? lengths[i] : n, XQC_MOQT_GROUP_ASCENDING, &h, &o) > 0);
        CU_ASSERT_EQUAL(o.object_id, ids[i]);
        CU_ASSERT_EQUAL(o.group_id, groups[i]);
    }
}

void
xqc_test_moqt_fetch_codec_errors(void)
{
    const uint8_t invalid[][8] = {
        {0},                         /* First record inherits Group/Object. */
        {0x0d, 0, 0, 0},             /* First record inherits Subgroup. */
        {0x0c, 0, 0, 0},             /* First record inherits Priority. */
        {0x80, 0x80},                /* Undefined Range serialization. */
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        xqc_moqt_fetch_history_t h;
        xqc_memzero(&h, sizeof(h));
        xqc_moqt_object_t o;
        CU_ASSERT_EQUAL(xqc_moqt_fetch_header_decode(invalid[i],
            sizeof(invalid[i]), XQC_MOQT_GROUP_ASCENDING, &h, &o),
            -XQC_EILLEGAL_FRAME);
        CU_ASSERT_FALSE(h.has_location);
    }
    xqc_moqt_fetch_history_t h = {.location = {1, UINT64_MAX},
        .has_location = 1, .has_subgroup = 1, .subgroup_id = UINT64_MAX,
        .has_priority = 1};
    xqc_moqt_object_t o;
    const uint8_t subgroup[] = {2, 0}, object[] = {0, 0};
    CU_ASSERT_EQUAL(xqc_moqt_fetch_header_decode(subgroup, sizeof(subgroup),
        XQC_MOQT_GROUP_ASCENDING, &h, &o), -XQC_EILLEGAL_FRAME);
    CU_ASSERT_EQUAL(xqc_moqt_fetch_header_decode(object, sizeof(object),
        XQC_MOQT_GROUP_ASCENDING, &h, &o), -XQC_EILLEGAL_FRAME);
    const uint8_t group[] = {8, 1, 0};
    CU_ASSERT_EQUAL(xqc_moqt_fetch_header_decode(group, sizeof(group),
        XQC_MOQT_GROUP_DESCENDING, &h, &o), -XQC_EILLEGAL_FRAME);
    h.location.group_id = UINT64_MAX;
    CU_ASSERT_EQUAL(xqc_moqt_fetch_header_decode(group, sizeof(group),
        XQC_MOQT_GROUP_ASCENDING, &h, &o), -XQC_EILLEGAL_FRAME);
    xqc_memzero(&h, sizeof(h));
    for (unsigned scenario = 0; scenario < 6; scenario++) {
        xqc_memzero(&o, sizeof(o));
        switch (scenario) {
        case 0: o.status = XQC_MOQT_OBJECT_END_GROUP; break;
        case 1: o.range = XQC_MOQT_RANGE_TIMEOUT + 1; break;
        case 2: o.range = XQC_MOQT_RANGE_UNKNOWN; o.payload_length = 1; break;
        case 3: o.properties.iov_len = 1; break;
        case 4: o.properties.iov_len = XQC_MOQT_KV_MAX_VALUE + 1; break;
        case 5: h.has_location = 1; break;
        }
        CU_ASSERT_EQUAL(xqc_moqt_fetch_header_encode(XQC_MOQT_GROUP_ASCENDING,
            &h, &o, NULL, 0), -XQC_EPARAM);
    }
}
