#ifndef _XQC_MOQ_D18_PROPERTIES_H_INCLUDED_
#define _XQC_MOQ_D18_PROPERTIES_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

typedef enum {
    XQC_MOQ_D18_PROPERTY_SCOPE_TRACK,
    XQC_MOQ_D18_PROPERTY_SCOPE_OBJECT,
} xqc_moq_d18_property_scope_t;

typedef enum {
    XQC_MOQ_D18_PROPERTY_OK = 0,
    XQC_MOQ_D18_PROPERTY_INVALID_ARGUMENT = -1,
    XQC_MOQ_D18_PROPERTY_FORMATTING = -2,
    XQC_MOQ_D18_PROPERTY_PROTOCOL_VIOLATION = -3,
    XQC_MOQ_D18_PROPERTY_UNSUPPORTED_EXTENSION = -4,
    XQC_MOQ_D18_PROPERTY_NO_MEMORY = -5,
    XQC_MOQ_D18_PROPERTY_NO_SPACE = -6,
} xqc_moq_d18_property_result_t;

typedef enum {
    XQC_MOQ_D18_PROPERTY_OBJECT_DELIVERY_TIMEOUT = 0x02,
    XQC_MOQ_D18_PROPERTY_MAX_CACHE_DURATION = 0x04,
    XQC_MOQ_D18_PROPERTY_SUBGROUP_DELIVERY_TIMEOUT = 0x06,
    XQC_MOQ_D18_PROPERTY_IMMUTABLE_PROPERTIES = 0x0b,
    XQC_MOQ_D18_PROPERTY_DEFAULT_PUBLISHER_PRIORITY = 0x0e,
    XQC_MOQ_D18_PROPERTY_DEFAULT_PUBLISHER_GROUP_ORDER = 0x22,
    XQC_MOQ_D18_PROPERTY_DYNAMIC_GROUPS = 0x30,
    XQC_MOQ_D18_PROPERTY_PRIOR_GROUP_ID_GAP = 0x3c,
    XQC_MOQ_D18_PROPERTY_PRIOR_OBJECT_ID_GAP = 0x3e,
} xqc_moq_d18_property_type_t;

typedef struct xqc_moq_d18_properties_s xqc_moq_d18_properties_t;

typedef struct {
    uint64_t type;
    uint8_t is_bytes;
    uint8_t known;
    uint64_t integer;
    const uint8_t *bytes;
    size_t bytes_len;
    const uint8_t *encoded;
    size_t encoded_len;
    const xqc_moq_d18_properties_t *immutable;
} xqc_moq_d18_property_view_t;

xqc_moq_d18_property_result_t xqc_moq_d18_properties_parse(
    xqc_moq_d18_property_scope_t scope, const uint8_t *wire,
    size_t wire_len, xqc_moq_d18_properties_t **properties);

void xqc_moq_d18_properties_destroy(
    xqc_moq_d18_properties_t *properties);

xqc_moq_d18_property_result_t xqc_moq_d18_properties_clone(
    const xqc_moq_d18_properties_t *properties,
    xqc_moq_d18_properties_t **clone);

size_t xqc_moq_d18_properties_count(
    const xqc_moq_d18_properties_t *properties);

const xqc_moq_d18_property_view_t *xqc_moq_d18_properties_at(
    const xqc_moq_d18_properties_t *properties, size_t index);

const xqc_moq_d18_property_view_t *xqc_moq_d18_properties_find(
    const xqc_moq_d18_properties_t *properties, uint64_t type,
    size_t occurrence);

const uint8_t *xqc_moq_d18_properties_wire(
    const xqc_moq_d18_properties_t *properties, size_t *wire_len);

xqc_moq_d18_property_result_t xqc_moq_d18_properties_write(
    const xqc_moq_d18_properties_t *properties, uint8_t *buf,
    size_t buf_cap, size_t *written);

#endif /* _XQC_MOQ_D18_PROPERTIES_H_INCLUDED_ */
