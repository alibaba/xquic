#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "moq/moq_transport/draft18/xqc_moq_d18_data.h"
#include "moq/moq_transport/xqc_moq_stream.h"
#include "moq/moq_transport/version/xqc_moq_version.h"

#define XQC_TEST_ASSERT(expr) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "assert failed: %s:%d: %s\n", \
                    __FILE__, __LINE__, #expr); \
            return -1; \
        } \
    } while (0)

static int
xqc_test_d18_datagram_vectors(void)
{
    static uint8_t payload[] = {'A'};
    static uint8_t properties[] = {0x3e, 0x01};
    static const uint8_t compact_wire[] = {0x0c, 0x01, 0x02, 'A'};
    static const uint8_t properties_wire[] = {
        0x01, 0x01, 0x02, 0x03, 0x07, 0x02, 0x3e, 0x01, 'A'
    };
    static const uint8_t status_wire[] = {0x2c, 0x01, 0x02, 0x04};
    uint8_t encoded[64] = {0};
    xqc_moq_object_t object;
    xqc_moq_object_t decoded;

    memset(&object, 0, sizeof(object));
    object.track_alias = 1;
    object.group_id = 2;
    object.payload = payload;
    object.payload_len = sizeof(payload);
    XQC_TEST_ASSERT(xqc_moq_d18_object_datagram_encode(
        &object, encoded, sizeof(encoded)) == (xqc_int_t)sizeof(compact_wire));
    XQC_TEST_ASSERT(memcmp(encoded, compact_wire, sizeof(compact_wire)) == 0);

    memset(&object, 0, sizeof(object));
    object.track_alias = 1;
    object.group_id = 2;
    object.object_id = 3;
    object.publisher_priority_set = 1;
    object.publisher_priority = 7;
    object.object_properties_present = 1;
    object.object_properties = properties;
    object.object_properties_len = sizeof(properties);
    object.payload = payload;
    object.payload_len = sizeof(payload);
    XQC_TEST_ASSERT(xqc_moq_d18_object_datagram_encode(
        &object, encoded, sizeof(encoded))
        == (xqc_int_t)sizeof(properties_wire));
    XQC_TEST_ASSERT(memcmp(encoded, properties_wire,
                           sizeof(properties_wire)) == 0);

    memset(&decoded, 0, sizeof(decoded));
    XQC_TEST_ASSERT(xqc_moq_d18_object_datagram_decode(
        properties_wire, sizeof(properties_wire), &decoded) == XQC_OK);
    XQC_TEST_ASSERT(decoded.track_alias == 1 && decoded.group_id == 2);
    XQC_TEST_ASSERT(decoded.object_id == 3);
    XQC_TEST_ASSERT(decoded.publisher_priority_set == 1);
    XQC_TEST_ASSERT(decoded.publisher_priority == 7);
    XQC_TEST_ASSERT(decoded.object_properties_present == 1);
    XQC_TEST_ASSERT(decoded.object_properties_len == sizeof(properties));
    XQC_TEST_ASSERT(memcmp(decoded.object_properties, properties,
                           sizeof(properties)) == 0);
    XQC_TEST_ASSERT(decoded.payload_len == 1 && decoded.payload[0] == 'A');
    xqc_moq_d18_object_free_fields(&decoded);

    memset(&object, 0, sizeof(object));
    object.track_alias = 1;
    object.group_id = 2;
    object.status = XQC_MOQ_OBJ_STATUS_TRACK_END;
    XQC_TEST_ASSERT(xqc_moq_d18_object_datagram_encode(
        &object, encoded, sizeof(encoded)) == (xqc_int_t)sizeof(status_wire));
    XQC_TEST_ASSERT(memcmp(encoded, status_wire, sizeof(status_wire)) == 0);

    memset(&decoded, 0, sizeof(decoded));
    XQC_TEST_ASSERT(xqc_moq_d18_object_datagram_decode(
        status_wire, sizeof(status_wire), &decoded) == XQC_OK);
    XQC_TEST_ASSERT(decoded.status == XQC_MOQ_OBJ_STATUS_TRACK_END);
    XQC_TEST_ASSERT(decoded.payload_len == 0);
    xqc_moq_d18_object_free_fields(&decoded);
    return 0;
}

static int
xqc_test_d18_datagram_rejects_invalid_combinations(void)
{
    static const uint8_t invalid_type[] = {0x22, 0x00, 0x00, 0x03};
    static const uint8_t empty_properties[] = {
        0x0d, 0x00, 0x00, 0x00
    };
    static const uint8_t status_with_properties[] = {
        0x21, 0x00, 0x00, 0x00, 0x03
    };
    xqc_moq_object_t decoded;

    memset(&decoded, 0, sizeof(decoded));
    XQC_TEST_ASSERT(xqc_moq_d18_object_datagram_decode(
        invalid_type, sizeof(invalid_type), &decoded) == -XQC_EPROTO);
    XQC_TEST_ASSERT(xqc_moq_d18_object_datagram_decode(
        empty_properties, sizeof(empty_properties), &decoded) == -XQC_EPROTO);
    XQC_TEST_ASSERT(xqc_moq_d18_object_datagram_decode(
        status_with_properties, sizeof(status_with_properties), &decoded)
        == -XQC_EPROTO);
    return 0;
}

static int
xqc_test_decode_fragmented_subgroup(const uint8_t *wire, size_t wire_len,
    xqc_moq_d18_data_msg_t **decoded_out)
{
    xqc_moq_d18_data_msg_t *decoded = xqc_moq_d18_data_msg_create();
    xqc_moq_decode_msg_ctx_t ctx;
    xqc_int_t finish = 0;
    xqc_int_t wait = 0;

    XQC_TEST_ASSERT(decoded != NULL && wire_len > 1);
    xqc_moq_decode_msg_ctx_reset(&ctx);
    ctx.cur_msg_type = wire[0];
    xqc_moq_d18_subgroup_header_init(&decoded->msg_base);
    for (size_t i = 1; i < wire_len; i++) {
        finish = 0;
        wait = 0;
        xqc_int_t ret = decoded->msg_base.decode(
            (uint8_t *)wire + i, 1, i + 1 == wire_len, &ctx,
            &decoded->msg_base, &finish, &wait);
        XQC_TEST_ASSERT(ret == 1);
        XQC_TEST_ASSERT(i + 1 == wire_len ? finish == 1 : wait == 1);
    }
    *decoded_out = decoded;
    return 0;
}

static int
xqc_test_d18_subgroup_vectors_and_fragmentation(void)
{
    static const uint8_t first_wire[] = {
        0x5d, 0x01, 0x02, 0x03, 0x07,
        0x05, 0x02, 0x3e, 0x01, 0x01, 'A'
    };
    static const uint8_t next_wire[] = {0x01, 0x00, 0x00, 0x04};
    xqc_moq_d18_data_msg_t *decoded = NULL;
    xqc_moq_d18_data_msg_t *next = NULL;
    xqc_moq_decode_msg_ctx_t ctx;
    xqc_int_t finish = 0;
    xqc_int_t wait = 0;

    XQC_TEST_ASSERT(xqc_test_decode_fragmented_subgroup(
        first_wire, sizeof(first_wire), &decoded) == 0);
    XQC_TEST_ASSERT(decoded->has_object == 1);
    XQC_TEST_ASSERT(decoded->object.track_alias == 1);
    XQC_TEST_ASSERT(decoded->object.group_id == 2);
    XQC_TEST_ASSERT(decoded->object.subgroup_id == 3);
    XQC_TEST_ASSERT(decoded->object.object_id_delta == 5);
    XQC_TEST_ASSERT(decoded->object.object_id == 5);
    XQC_TEST_ASSERT(decoded->object.publisher_priority_set == 1);
    XQC_TEST_ASSERT(decoded->object.publisher_priority == 7);
    XQC_TEST_ASSERT(decoded->object.first_of_subgroup == 1);
    XQC_TEST_ASSERT(decoded->object.end_of_group == 1);
    XQC_TEST_ASSERT(decoded->object.end_of_stream == 1);
    XQC_TEST_ASSERT(decoded->object.object_properties_len == 2);
    XQC_TEST_ASSERT(decoded->object.payload_len == 1);
    XQC_TEST_ASSERT(decoded->object.payload[0] == 'A');

    next = xqc_moq_d18_data_msg_create();
    XQC_TEST_ASSERT(next != NULL);
    xqc_moq_d18_subgroup_object_init(&next->msg_base);
    xqc_moq_d18_data_msg_inherit_subgroup(next, decoded);
    xqc_moq_d18_data_msg_set_previous(next, 2, 5, 3, 7, 1);
    xqc_moq_decode_msg_ctx_reset(&ctx);
    XQC_TEST_ASSERT(next->msg_base.decode(
        (uint8_t *)next_wire, sizeof(next_wire), 1, &ctx,
        &next->msg_base, &finish, &wait) == (xqc_int_t)sizeof(next_wire));
    XQC_TEST_ASSERT(finish == 1 && wait == 0);
    XQC_TEST_ASSERT(next->object.object_id_delta == 1);
    XQC_TEST_ASSERT(next->object.object_id == 7);
    XQC_TEST_ASSERT(next->object.status == XQC_MOQ_OBJ_STATUS_TRACK_END);
    XQC_TEST_ASSERT(next->object.object_properties_present == 1);
    XQC_TEST_ASSERT(next->object.object_properties_len == 0);

    xqc_moq_d18_data_msg_destroy(next);
    xqc_moq_d18_data_msg_destroy(decoded);
    return 0;
}

static int
xqc_test_d18_subgroup_delta_overflow(void)
{
    static const uint8_t wire[] = {0x00, 0x01, 'x'};
    xqc_moq_d18_data_msg_t *msg = xqc_moq_d18_data_msg_create();
    xqc_moq_decode_msg_ctx_t ctx;
    xqc_int_t finish = 0;
    xqc_int_t wait = 0;

    XQC_TEST_ASSERT(msg != NULL);
    xqc_moq_d18_subgroup_object_init(&msg->msg_base);
    msg->subgroup_wire_type = 0x10;
    xqc_moq_d18_data_msg_set_previous(
        msg, 1, UINT64_MAX, 0, 0, 1);
    xqc_moq_decode_msg_ctx_reset(&ctx);
    XQC_TEST_ASSERT(msg->msg_base.decode(
        (uint8_t *)wire, sizeof(wire), 1, &ctx, &msg->msg_base,
        &finish, &wait) == -XQC_EPROTO);
    xqc_moq_d18_data_msg_destroy(msg);
    return 0;
}

static int
xqc_test_d18_fetch_vectors(void)
{
    static const uint8_t first_wire[] = {
        0x3f, 0x02, 0x03, 0x04, 0x07,
        0x02, 0x3e, 0x01, 0x01, 'A'
    };
    static const uint8_t next_wire[] = {0x01, 0x01, 'B'};
    static const uint8_t next_group_wire[] = {0x0e, 0x01, 0x00, 0x01, 'C'};
    static const uint8_t unknown_range_wire[] = {0x81, 0x0c, 0x01, 0x09};
    xqc_moq_d18_data_msg_t *msg = NULL;
    xqc_moq_decode_msg_ctx_t ctx;
    xqc_int_t finish = 0;
    xqc_int_t wait = 0;

#define XQC_DECODE_FETCH(bytes, previous_valid, group, object_id, subgroup, prio, actual_valid) \
    do { \
        msg = xqc_moq_d18_data_msg_create(); \
        XQC_TEST_ASSERT(msg != NULL); \
        xqc_moq_d18_fetch_object_init(&msg->msg_base); \
        msg->group_order = XQC_MOQ_GROUP_ORDER_ASCENDING; \
        xqc_moq_d18_data_msg_set_previous( \
            msg, (group), (object_id), (subgroup), (prio), (previous_valid)); \
        msg->previous_actual_valid = (actual_valid); \
        xqc_moq_decode_msg_ctx_reset(&ctx); \
        finish = 0; wait = 0; \
        XQC_TEST_ASSERT(msg->msg_base.decode( \
            (uint8_t *)(bytes), sizeof(bytes), 1, &ctx, &msg->msg_base, \
            &finish, &wait) == (xqc_int_t)sizeof(bytes)); \
        XQC_TEST_ASSERT(finish == 1 && wait == 0); \
    } while (0)

    XQC_DECODE_FETCH(first_wire, 0, 0, 0, 0, 0, 0);
    XQC_TEST_ASSERT(msg->record_kind == XQC_MOQ_D18_RECORD_OBJECT);
    XQC_TEST_ASSERT(msg->object.group_id == 2);
    XQC_TEST_ASSERT(msg->object.subgroup_id == 3);
    XQC_TEST_ASSERT(msg->object.object_id == 4);
    XQC_TEST_ASSERT(msg->object.payload_len == 1);
    xqc_moq_d18_data_msg_destroy(msg);

    XQC_DECODE_FETCH(next_wire, 1, 2, 4, 3, 7, 1);
    XQC_TEST_ASSERT(msg->object.group_id == 2);
    XQC_TEST_ASSERT(msg->object.subgroup_id == 3);
    XQC_TEST_ASSERT(msg->object.object_id == 5);
    XQC_TEST_ASSERT(msg->object.publisher_priority == 7);
    xqc_moq_d18_data_msg_destroy(msg);

    XQC_DECODE_FETCH(next_group_wire, 1, 2, 5, 3, 7, 1);
    XQC_TEST_ASSERT(msg->object.group_id == 4);
    XQC_TEST_ASSERT(msg->object.subgroup_id == 4);
    XQC_TEST_ASSERT(msg->object.object_id == 0);
    xqc_moq_d18_data_msg_destroy(msg);

    XQC_DECODE_FETCH(unknown_range_wire, 1, 4, 0, 4, 7, 1);
    XQC_TEST_ASSERT(msg->record_kind == XQC_MOQ_D18_RECORD_UNKNOWN_RANGE);
    XQC_TEST_ASSERT(msg->object.group_id == 6);
    XQC_TEST_ASSERT(msg->object.object_id == 9);
    xqc_moq_d18_data_msg_destroy(msg);

#undef XQC_DECODE_FETCH
    return 0;
}

static int
xqc_test_d18_fetch_zero_length_and_reference_rules(void)
{
    static const uint8_t zero_payload[] = {
        0x1f, 0x01, 0x00, 0x00, 0x05, 0x00
    };
    static const uint8_t invalid_first[] = {0x00, 0x01, 'x'};
    static const uint8_t descending_underflow[] = {
        0x1c, 0x00, 0x00, 0x05, 0x01, 'x'
    };
    xqc_moq_d18_data_msg_t *msg = xqc_moq_d18_data_msg_create();
    xqc_moq_decode_msg_ctx_t ctx;
    xqc_int_t finish = 0;
    xqc_int_t wait = 0;

    XQC_TEST_ASSERT(msg != NULL);
    xqc_moq_d18_fetch_object_init(&msg->msg_base);
    msg->group_order = XQC_MOQ_GROUP_ORDER_ASCENDING;
    xqc_moq_decode_msg_ctx_reset(&ctx);
    XQC_TEST_ASSERT(msg->msg_base.decode(
        (uint8_t *)zero_payload, sizeof(zero_payload), 1, &ctx,
        &msg->msg_base, &finish, &wait)
        == (xqc_int_t)sizeof(zero_payload));
    XQC_TEST_ASSERT(finish == 1 && msg->object.payload_len == 0);
    XQC_TEST_ASSERT(msg->object.status == XQC_MOQ_OBJ_STATUS_NORMAL);
    xqc_moq_d18_data_msg_destroy(msg);

    msg = xqc_moq_d18_data_msg_create();
    XQC_TEST_ASSERT(msg != NULL);
    xqc_moq_d18_fetch_object_init(&msg->msg_base);
    msg->group_order = XQC_MOQ_GROUP_ORDER_ASCENDING;
    xqc_moq_decode_msg_ctx_reset(&ctx);
    XQC_TEST_ASSERT(msg->msg_base.decode(
        (uint8_t *)invalid_first, sizeof(invalid_first), 1, &ctx,
        &msg->msg_base, &finish, &wait) == -XQC_EPROTO);
    xqc_moq_d18_data_msg_destroy(msg);

    msg = xqc_moq_d18_data_msg_create();
    XQC_TEST_ASSERT(msg != NULL);
    xqc_moq_d18_fetch_object_init(&msg->msg_base);
    msg->group_order = XQC_MOQ_GROUP_ORDER_DESCENDING;
    xqc_moq_d18_data_msg_set_previous(msg, 0, 0, 0, 5, 1);
    msg->previous_actual_valid = 1;
    xqc_moq_decode_msg_ctx_reset(&ctx);
    XQC_TEST_ASSERT(msg->msg_base.decode(
        (uint8_t *)descending_underflow, sizeof(descending_underflow), 1,
        &ctx, &msg->msg_base, &finish, &wait) == -XQC_EPROTO);
    xqc_moq_d18_data_msg_destroy(msg);
    return 0;
}

static int
xqc_test_d18_profile_routes_data_codecs(void)
{
    const xqc_moq_version_profile_t *profile = xqc_moq_v18_profile();
    const xqc_moq_message_codec_entry_t *codec = NULL;
    xqc_moq_stream_t stream;
    xqc_moq_stream_t request_stream;
    xqc_moq_d18_data_msg_t *msg;

    XQC_TEST_ASSERT(profile != NULL);
    XQC_TEST_ASSERT(xqc_moq_profile_has_capability(
        profile, XQC_MOQ_CAP_OBJECT_DATAGRAM));
    XQC_TEST_ASSERT(profile->decode_datagram == xqc_moq_d18_decode_datagram);

    codec = xqc_moq_profile_find_codec(
        profile, XQC_MOQ_STREAM_D18_SUBGROUP, 0x5d);
    XQC_TEST_ASSERT(codec != NULL);
    XQC_TEST_ASSERT(codec->semantic == XQC_MOQ_SEMANTIC_SUBGROUP);
    XQC_TEST_ASSERT(codec->create == (void *(*)(void))xqc_moq_d18_data_msg_create);
    XQC_TEST_ASSERT(xqc_moq_profile_next_data_codec(
        profile, XQC_MOQ_STREAM_D18_SUBGROUP, 0x5d, &codec));
    XQC_TEST_ASSERT(codec->semantic == XQC_MOQ_SEMANTIC_SUBGROUP_OBJECT);

    memset(&stream, 0, sizeof(stream));
    stream.subgroup_header_valid = 1;
    stream.subgroup_header.track_alias = 11;
    stream.subgroup_header.group_id = 12;
    stream.subgroup_header.subgroup_id = 13;
    stream.subgroup_header.subgroup_type = 0x5d;
    stream.subgroup_header.subgroup_priority = 14;
    stream.subgroup_header.properties_present = 1;
    stream.subgroup_prev_object_id = 15;
    stream.subgroup_prev_object_id_valid = 1;
    msg = xqc_moq_d18_data_msg_create();
    XQC_TEST_ASSERT(msg != NULL);
    codec->initialize(&msg->msg_base);
    XQC_TEST_ASSERT(profile->prepare_data_message(
        &stream, codec, &msg->msg_base) == XQC_OK);
    XQC_TEST_ASSERT(msg->object.track_alias == 11);
    XQC_TEST_ASSERT(msg->object.group_id == 12);
    XQC_TEST_ASSERT(msg->object.subgroup_id == 13);
    XQC_TEST_ASSERT(msg->subgroup_wire_type == 0x5d);
    XQC_TEST_ASSERT(msg->previous_valid == 1);
    XQC_TEST_ASSERT(msg->previous_object_id == 15);
    xqc_moq_d18_data_msg_destroy(msg);

    XQC_TEST_ASSERT(xqc_moq_profile_next_data_codec(
        profile, XQC_MOQ_STREAM_D18_FETCH,
        XQC_MOQ_D18_STREAM_TYPE_FETCH, &codec));
    XQC_TEST_ASSERT(codec->semantic == XQC_MOQ_SEMANTIC_FETCH_OBJECT);
    memset(&stream, 0, sizeof(stream));
    memset(&request_stream, 0, sizeof(request_stream));
    request_stream.d18_fetch_group_order = XQC_MOQ_GROUP_ORDER_DESCENDING;
    stream.fetch_request_stream = &request_stream;
    stream.d18_fetch_previous_valid = 1;
    stream.d18_fetch_previous_actual_valid = 1;
    stream.d18_fetch_previous_group_id = 21;
    stream.d18_fetch_previous_object_id = 22;
    stream.d18_fetch_previous_subgroup_id = 23;
    stream.d18_fetch_previous_priority = 24;
    msg = xqc_moq_d18_data_msg_create();
    XQC_TEST_ASSERT(msg != NULL);
    codec->initialize(&msg->msg_base);
    XQC_TEST_ASSERT(profile->prepare_data_message(
        &stream, codec, &msg->msg_base) == XQC_OK);
    XQC_TEST_ASSERT(msg->group_order == XQC_MOQ_GROUP_ORDER_DESCENDING);
    XQC_TEST_ASSERT(msg->previous_group_id == 21);
    XQC_TEST_ASSERT(msg->previous_object_id == 22);
    XQC_TEST_ASSERT(msg->previous_subgroup_id == 23);
    XQC_TEST_ASSERT(msg->previous_priority == 24);
    XQC_TEST_ASSERT(msg->previous_actual_valid == 1);
    xqc_moq_d18_data_msg_destroy(msg);
    return 0;
}

int
main(void)
{
    if (xqc_test_d18_datagram_vectors() != 0
        || xqc_test_d18_datagram_rejects_invalid_combinations() != 0
        || xqc_test_d18_subgroup_vectors_and_fragmentation() != 0
        || xqc_test_d18_subgroup_delta_overflow() != 0
        || xqc_test_d18_fetch_vectors() != 0
        || xqc_test_d18_fetch_zero_length_and_reference_rules() != 0
        || xqc_test_d18_profile_routes_data_codecs() != 0)
    {
        return 1;
    }
    printf("moq draft-18 data tests passed\n");
    return 0;
}
