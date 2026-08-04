#include <stdio.h>
#include <string.h>

#include "moq/moq_transport/draft18/xqc_moq_d18_properties.h"

#define XQC_TEST_ASSERT(expr) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "assert failed: %s:%d: %s\n", \
                    __FILE__, __LINE__, #expr); \
            return -1; \
        } \
    } while (0)

static int
xqc_test_empty_track_properties(void)
{
    xqc_moq_d18_properties_t *properties = NULL;
    XQC_TEST_ASSERT(xqc_moq_d18_properties_parse(
        XQC_MOQ_D18_PROPERTY_SCOPE_TRACK, NULL, 0, &properties)
        == XQC_MOQ_D18_PROPERTY_OK);
    XQC_TEST_ASSERT(properties != NULL);
    XQC_TEST_ASSERT(xqc_moq_d18_properties_count(properties) == 0);
    xqc_moq_d18_properties_destroy(properties);
    return 0;
}

static int
xqc_test_track_properties_exact_wire(void)
{
    static const uint8_t wire[] = {
        0x02, 0x81, 0x2c,
        0x02, 0x83, 0xe8,
        0x35, 0x02, 'x', 'y',
    };
    uint8_t output[sizeof(wire)] = {0};
    size_t output_len = 0;
    size_t wire_len = 0;
    xqc_moq_d18_properties_t *properties = NULL;
    xqc_moq_d18_properties_t *clone = NULL;

    XQC_TEST_ASSERT(xqc_moq_d18_properties_parse(
        XQC_MOQ_D18_PROPERTY_SCOPE_TRACK, wire, sizeof(wire),
        &properties) == XQC_MOQ_D18_PROPERTY_OK);
    XQC_TEST_ASSERT(xqc_moq_d18_properties_count(properties) == 3);

    const xqc_moq_d18_property_view_t *property =
        xqc_moq_d18_properties_at(properties, 0);
    XQC_TEST_ASSERT(property != NULL);
    XQC_TEST_ASSERT(property->type
                    == XQC_MOQ_D18_PROPERTY_OBJECT_DELIVERY_TIMEOUT);
    XQC_TEST_ASSERT(property->known == 1);
    XQC_TEST_ASSERT(property->is_bytes == 0);
    XQC_TEST_ASSERT(property->integer == 300);
    XQC_TEST_ASSERT(property->encoded_len == 3);
    XQC_TEST_ASSERT(memcmp(property->encoded, wire, 3) == 0);

    property = xqc_moq_d18_properties_at(properties, 1);
    XQC_TEST_ASSERT(property != NULL);
    XQC_TEST_ASSERT(property->type
                    == XQC_MOQ_D18_PROPERTY_MAX_CACHE_DURATION);
    XQC_TEST_ASSERT(property->integer == 1000);

    property = xqc_moq_d18_properties_at(properties, 2);
    XQC_TEST_ASSERT(property != NULL);
    XQC_TEST_ASSERT(property->type == 0x39);
    XQC_TEST_ASSERT(property->known == 0);
    XQC_TEST_ASSERT(property->is_bytes == 1);
    XQC_TEST_ASSERT(property->bytes_len == 2);
    XQC_TEST_ASSERT(memcmp(property->bytes, "xy", 2) == 0);
    XQC_TEST_ASSERT(xqc_moq_d18_properties_at(properties, 3) == NULL);

    property = xqc_moq_d18_properties_find(
        properties, XQC_MOQ_D18_PROPERTY_MAX_CACHE_DURATION, 0);
    XQC_TEST_ASSERT(property != NULL && property->integer == 1000);
    XQC_TEST_ASSERT(xqc_moq_d18_properties_find(
        properties, XQC_MOQ_D18_PROPERTY_MAX_CACHE_DURATION, 1) == NULL);

    const uint8_t *owned_wire =
        xqc_moq_d18_properties_wire(properties, &wire_len);
    XQC_TEST_ASSERT(owned_wire != NULL && owned_wire != wire);
    XQC_TEST_ASSERT(wire_len == sizeof(wire));
    XQC_TEST_ASSERT(memcmp(owned_wire, wire, sizeof(wire)) == 0);

    XQC_TEST_ASSERT(xqc_moq_d18_properties_clone(properties, &clone)
                    == XQC_MOQ_D18_PROPERTY_OK);
    const uint8_t *clone_wire =
        xqc_moq_d18_properties_wire(clone, &wire_len);
    XQC_TEST_ASSERT(clone_wire != NULL && clone_wire != owned_wire);
    XQC_TEST_ASSERT(wire_len == sizeof(wire));
    XQC_TEST_ASSERT(memcmp(clone_wire, wire, sizeof(wire)) == 0);

    XQC_TEST_ASSERT(xqc_moq_d18_properties_write(
        properties, output, sizeof(output), &output_len)
        == XQC_MOQ_D18_PROPERTY_OK);
    XQC_TEST_ASSERT(output_len == sizeof(wire));
    XQC_TEST_ASSERT(memcmp(output, wire, sizeof(wire)) == 0);

    output_len = 7;
    XQC_TEST_ASSERT(xqc_moq_d18_properties_write(
        properties, output, sizeof(output) - 1, &output_len)
        == XQC_MOQ_D18_PROPERTY_NO_SPACE);
    XQC_TEST_ASSERT(output_len == 0);

    xqc_moq_d18_properties_destroy(clone);
    xqc_moq_d18_properties_destroy(properties);
    return 0;
}

static int
xqc_test_nonminimal_vi64_preserved(void)
{
    static const uint8_t wire[] = {
        0x80, 0x02,
        0x80, 0x01,
    };
    uint8_t output[sizeof(wire)] = {0};
    size_t output_len = 0;
    xqc_moq_d18_properties_t *properties = NULL;

    XQC_TEST_ASSERT(xqc_moq_d18_properties_parse(
        XQC_MOQ_D18_PROPERTY_SCOPE_TRACK, wire, sizeof(wire),
        &properties) == XQC_MOQ_D18_PROPERTY_OK);
    const xqc_moq_d18_property_view_t *property =
        xqc_moq_d18_properties_at(properties, 0);
    XQC_TEST_ASSERT(property != NULL);
    XQC_TEST_ASSERT(property->type
                    == XQC_MOQ_D18_PROPERTY_OBJECT_DELIVERY_TIMEOUT);
    XQC_TEST_ASSERT(property->integer == 1);
    XQC_TEST_ASSERT(property->encoded_len == sizeof(wire));
    XQC_TEST_ASSERT(xqc_moq_d18_properties_write(
        properties, output, sizeof(output), &output_len)
        == XQC_MOQ_D18_PROPERTY_OK);
    XQC_TEST_ASSERT(output_len == sizeof(wire));
    XQC_TEST_ASSERT(memcmp(output, wire, sizeof(wire)) == 0);

    xqc_moq_d18_properties_destroy(properties);
    return 0;
}

static int
xqc_test_property_scope_and_values(void)
{
    static const uint8_t track_priority_255[] = {0x0e, 0x80, 0xff};
    static const uint8_t track_priority_256[] = {0x0e, 0x81, 0x00};
    static const uint8_t group_order_1[] = {0x22, 0x01};
    static const uint8_t group_order_2[] = {0x22, 0x02};
    static const uint8_t group_order_0[] = {0x22, 0x00};
    static const uint8_t dynamic_groups_1[] = {0x30, 0x01};
    static const uint8_t dynamic_groups_2[] = {0x30, 0x02};
    static const uint8_t track_only[] = {0x02, 0x01};
    static const uint8_t object_gap[] = {0x3c, 0x01};
    static const uint8_t external_object_timestamp[] = {0x06, 0x01};
    xqc_moq_d18_properties_t *properties = NULL;

#define XQC_TEST_PARSE_OK(property_scope, bytes) \
    do { \
        XQC_TEST_ASSERT(xqc_moq_d18_properties_parse( \
            (property_scope), (bytes), sizeof(bytes), &properties) \
            == XQC_MOQ_D18_PROPERTY_OK); \
        xqc_moq_d18_properties_destroy(properties); \
        properties = NULL; \
    } while (0)

    XQC_TEST_PARSE_OK(
        XQC_MOQ_D18_PROPERTY_SCOPE_TRACK, track_priority_255);
    XQC_TEST_PARSE_OK(
        XQC_MOQ_D18_PROPERTY_SCOPE_TRACK, group_order_1);
    XQC_TEST_PARSE_OK(
        XQC_MOQ_D18_PROPERTY_SCOPE_TRACK, group_order_2);
    XQC_TEST_PARSE_OK(
        XQC_MOQ_D18_PROPERTY_SCOPE_TRACK, dynamic_groups_1);
    XQC_TEST_PARSE_OK(
        XQC_MOQ_D18_PROPERTY_SCOPE_OBJECT, object_gap);

    XQC_TEST_ASSERT(xqc_moq_d18_properties_parse(
        XQC_MOQ_D18_PROPERTY_SCOPE_OBJECT,
        external_object_timestamp, sizeof(external_object_timestamp),
        &properties) == XQC_MOQ_D18_PROPERTY_OK);
    const xqc_moq_d18_property_view_t *property =
        xqc_moq_d18_properties_at(properties, 0);
    XQC_TEST_ASSERT(property != NULL && property->type == 0x06);
    XQC_TEST_ASSERT(property->known == 0);
    xqc_moq_d18_properties_destroy(properties);
    properties = NULL;

    XQC_TEST_ASSERT(xqc_moq_d18_properties_parse(
        XQC_MOQ_D18_PROPERTY_SCOPE_TRACK,
        track_priority_256, sizeof(track_priority_256), &properties)
        == XQC_MOQ_D18_PROPERTY_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(properties == NULL);
    XQC_TEST_ASSERT(xqc_moq_d18_properties_parse(
        XQC_MOQ_D18_PROPERTY_SCOPE_TRACK,
        group_order_0, sizeof(group_order_0), &properties)
        == XQC_MOQ_D18_PROPERTY_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(xqc_moq_d18_properties_parse(
        XQC_MOQ_D18_PROPERTY_SCOPE_TRACK,
        dynamic_groups_2, sizeof(dynamic_groups_2), &properties)
        == XQC_MOQ_D18_PROPERTY_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(xqc_moq_d18_properties_parse(
        XQC_MOQ_D18_PROPERTY_SCOPE_OBJECT,
        track_only, sizeof(track_only), &properties)
        == XQC_MOQ_D18_PROPERTY_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(xqc_moq_d18_properties_parse(
        XQC_MOQ_D18_PROPERTY_SCOPE_TRACK,
        object_gap, sizeof(object_gap), &properties)
        == XQC_MOQ_D18_PROPERTY_PROTOCOL_VIOLATION);

#undef XQC_TEST_PARSE_OK
    return 0;
}

static int
xqc_test_mandatory_and_unknown_properties(void)
{
    static const uint8_t mandatory_min[] = {0xc0, 0x40, 0x00, 0x00};
    static const uint8_t mandatory_max[] = {0xc0, 0x7f, 0xff, 0x00};
    static const uint8_t above_mandatory[] = {0xc0, 0x80, 0x00, 0x00};
    static const uint8_t repeated_unknown[] = {
        0x39, 0x01, 'a',
        0x00, 0x01, 'b',
    };
    xqc_moq_d18_properties_t *properties = NULL;

    XQC_TEST_ASSERT(xqc_moq_d18_properties_parse(
        XQC_MOQ_D18_PROPERTY_SCOPE_TRACK,
        mandatory_min, sizeof(mandatory_min), &properties)
        == XQC_MOQ_D18_PROPERTY_UNSUPPORTED_EXTENSION);
    XQC_TEST_ASSERT(properties == NULL);
    XQC_TEST_ASSERT(xqc_moq_d18_properties_parse(
        XQC_MOQ_D18_PROPERTY_SCOPE_TRACK,
        mandatory_max, sizeof(mandatory_max), &properties)
        == XQC_MOQ_D18_PROPERTY_UNSUPPORTED_EXTENSION);
    XQC_TEST_ASSERT(xqc_moq_d18_properties_parse(
        XQC_MOQ_D18_PROPERTY_SCOPE_OBJECT,
        mandatory_min, sizeof(mandatory_min), &properties)
        == XQC_MOQ_D18_PROPERTY_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(xqc_moq_d18_properties_parse(
        XQC_MOQ_D18_PROPERTY_SCOPE_OBJECT,
        mandatory_max, sizeof(mandatory_max), &properties)
        == XQC_MOQ_D18_PROPERTY_PROTOCOL_VIOLATION);

    XQC_TEST_ASSERT(xqc_moq_d18_properties_parse(
        XQC_MOQ_D18_PROPERTY_SCOPE_TRACK,
        above_mandatory, sizeof(above_mandatory), &properties)
        == XQC_MOQ_D18_PROPERTY_OK);
    const xqc_moq_d18_property_view_t *property =
        xqc_moq_d18_properties_at(properties, 0);
    XQC_TEST_ASSERT(property != NULL && property->type == 0x8000);
    XQC_TEST_ASSERT(property->known == 0);
    xqc_moq_d18_properties_destroy(properties);
    properties = NULL;

    XQC_TEST_ASSERT(xqc_moq_d18_properties_parse(
        XQC_MOQ_D18_PROPERTY_SCOPE_TRACK,
        repeated_unknown, sizeof(repeated_unknown), &properties)
        == XQC_MOQ_D18_PROPERTY_OK);
    property = xqc_moq_d18_properties_find(properties, 0x39, 0);
    XQC_TEST_ASSERT(property != NULL && property->bytes_len == 1);
    XQC_TEST_ASSERT(property->bytes[0] == 'a');
    property = xqc_moq_d18_properties_find(properties, 0x39, 1);
    XQC_TEST_ASSERT(property != NULL && property->bytes_len == 1);
    XQC_TEST_ASSERT(property->bytes[0] == 'b');
    XQC_TEST_ASSERT(xqc_moq_d18_properties_find(
        properties, 0x39, 2) == NULL);
    xqc_moq_d18_properties_destroy(properties);
    return 0;
}

static int
xqc_test_immutable_properties(void)
{
    static const uint8_t immutable[] = {
        0x0b, 0x05,
        0x02, 0x05,
        0x37, 0x01, 'z',
    };
    static const uint8_t nested_immutable[] = {
        0x0b, 0x02,
        0x0b, 0x00,
    };
    static const uint8_t duplicate_immutable[] = {
        0x0b, 0x00,
        0x00, 0x00,
    };
    static const uint8_t duplicate_group_gap[] = {
        0x3c, 0x01,
        0x00, 0x02,
    };
    static const uint8_t duplicate_object_gap[] = {
        0x3e, 0x01,
        0x00, 0x02,
    };
    xqc_moq_d18_properties_t *properties = NULL;

    XQC_TEST_ASSERT(xqc_moq_d18_properties_parse(
        XQC_MOQ_D18_PROPERTY_SCOPE_TRACK,
        immutable, sizeof(immutable), &properties)
        == XQC_MOQ_D18_PROPERTY_OK);
    XQC_TEST_ASSERT(xqc_moq_d18_properties_count(properties) == 1);
    const xqc_moq_d18_property_view_t *container =
        xqc_moq_d18_properties_at(properties, 0);
    XQC_TEST_ASSERT(container != NULL);
    XQC_TEST_ASSERT(container->type
                    == XQC_MOQ_D18_PROPERTY_IMMUTABLE_PROPERTIES);
    XQC_TEST_ASSERT(container->immutable != NULL);
    XQC_TEST_ASSERT(xqc_moq_d18_properties_count(container->immutable) == 2);
    const xqc_moq_d18_property_view_t *property =
        xqc_moq_d18_properties_find(
            properties,
            XQC_MOQ_D18_PROPERTY_OBJECT_DELIVERY_TIMEOUT, 0);
    XQC_TEST_ASSERT(property != NULL && property->integer == 5);
    property = xqc_moq_d18_properties_find(properties, 0x39, 0);
    XQC_TEST_ASSERT(property != NULL && property->bytes_len == 1);
    XQC_TEST_ASSERT(property->bytes[0] == 'z');
    xqc_moq_d18_properties_destroy(properties);
    properties = NULL;

    XQC_TEST_ASSERT(xqc_moq_d18_properties_parse(
        XQC_MOQ_D18_PROPERTY_SCOPE_TRACK,
        nested_immutable, sizeof(nested_immutable), &properties)
        == XQC_MOQ_D18_PROPERTY_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(xqc_moq_d18_properties_parse(
        XQC_MOQ_D18_PROPERTY_SCOPE_OBJECT,
        duplicate_immutable, sizeof(duplicate_immutable), &properties)
        == XQC_MOQ_D18_PROPERTY_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(xqc_moq_d18_properties_parse(
        XQC_MOQ_D18_PROPERTY_SCOPE_OBJECT,
        duplicate_group_gap, sizeof(duplicate_group_gap), &properties)
        == XQC_MOQ_D18_PROPERTY_PROTOCOL_VIOLATION);
    XQC_TEST_ASSERT(xqc_moq_d18_properties_parse(
        XQC_MOQ_D18_PROPERTY_SCOPE_OBJECT,
        duplicate_object_gap, sizeof(duplicate_object_gap), &properties)
        == XQC_MOQ_D18_PROPERTY_PROTOCOL_VIOLATION);
    return 0;
}

static int
xqc_test_property_formatting(void)
{
    static const uint8_t missing_value[] = {0x02};
    static const uint8_t oversized_bytes[] = {0x0b, 0xc1, 0x00, 0x00};
    xqc_moq_d18_properties_t *properties = NULL;

    XQC_TEST_ASSERT(xqc_moq_d18_properties_parse(
        XQC_MOQ_D18_PROPERTY_SCOPE_TRACK,
        missing_value, sizeof(missing_value), &properties)
        == XQC_MOQ_D18_PROPERTY_FORMATTING);
    XQC_TEST_ASSERT(xqc_moq_d18_properties_parse(
        XQC_MOQ_D18_PROPERTY_SCOPE_TRACK,
        oversized_bytes, sizeof(oversized_bytes), &properties)
        == XQC_MOQ_D18_PROPERTY_FORMATTING);
    XQC_TEST_ASSERT(xqc_moq_d18_properties_parse(
        XQC_MOQ_D18_PROPERTY_SCOPE_TRACK, NULL, 1, &properties)
        == XQC_MOQ_D18_PROPERTY_INVALID_ARGUMENT);
    XQC_TEST_ASSERT(xqc_moq_d18_properties_parse(
        (xqc_moq_d18_property_scope_t)2, NULL, 0, &properties)
        == XQC_MOQ_D18_PROPERTY_INVALID_ARGUMENT);
    return 0;
}

int
main(void)
{
    if (xqc_test_empty_track_properties() != 0
        || xqc_test_track_properties_exact_wire() != 0
        || xqc_test_nonminimal_vi64_preserved() != 0
        || xqc_test_property_scope_and_values() != 0
        || xqc_test_mandatory_and_unknown_properties() != 0
        || xqc_test_immutable_properties() != 0
        || xqc_test_property_formatting() != 0)
    {
        return 1;
    }
    printf("moq_d18_properties_test: PASS\n");
    return 0;
}
