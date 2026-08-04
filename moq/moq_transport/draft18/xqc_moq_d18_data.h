#ifndef _XQC_MOQ_D18_DATA_H_INCLUDED_
#define _XQC_MOQ_D18_DATA_H_INCLUDED_

#include "moq/moq_transport/xqc_moq_message.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_defs.h"

#define XQC_MOQ_D18_DGRAM_PROPERTIES       0x01
#define XQC_MOQ_D18_DGRAM_END_OF_GROUP     0x02
#define XQC_MOQ_D18_DGRAM_ZERO_OBJECT_ID   0x04
#define XQC_MOQ_D18_DGRAM_DEFAULT_PRIORITY 0x08
#define XQC_MOQ_D18_DGRAM_STATUS           0x20

#define XQC_MOQ_D18_SUBGROUP_BASE             0x10
#define XQC_MOQ_D18_SUBGROUP_PROPERTIES       0x01
#define XQC_MOQ_D18_SUBGROUP_ID_MASK          0x06
#define XQC_MOQ_D18_SUBGROUP_END_OF_GROUP     0x08
#define XQC_MOQ_D18_SUBGROUP_DEFAULT_PRIORITY 0x20
#define XQC_MOQ_D18_SUBGROUP_FIRST_OBJECT     0x40

#define XQC_MOQ_D18_FETCH_SUBGROUP_MASK 0x03
#define XQC_MOQ_D18_FETCH_OBJECT_ID     0x04
#define XQC_MOQ_D18_FETCH_GROUP_ID      0x08
#define XQC_MOQ_D18_FETCH_PRIORITY      0x10
#define XQC_MOQ_D18_FETCH_PROPERTIES    0x20
#define XQC_MOQ_D18_FETCH_DATAGRAM      0x40
#define XQC_MOQ_D18_FETCH_RANGE_MISSING 0x8c
#define XQC_MOQ_D18_FETCH_RANGE_UNKNOWN 0x10c

typedef enum {
    XQC_MOQ_D18_RECORD_NONE = 0,
    XQC_MOQ_D18_RECORD_OBJECT,
    XQC_MOQ_D18_RECORD_MISSING_RANGE,
    XQC_MOQ_D18_RECORD_UNKNOWN_RANGE,
} xqc_moq_d18_record_kind_t;

typedef struct xqc_moq_d18_data_msg_s {
    xqc_moq_msg_base_t          msg_base;
    xqc_moq_object_t            object;
    xqc_moq_d18_record_kind_t   record_kind;
    uint64_t                    request_id;
    uint64_t                    subgroup_wire_type;
    uint64_t                    serialization_flags;
    uint64_t                    encoded_group_id;
    uint64_t                    encoded_object_id;
    uint64_t                    previous_group_id;
    uint64_t                    previous_object_id;
    uint64_t                    previous_subgroup_id;
    uint8_t                     previous_priority;
    uint8_t                     previous_valid;
    uint8_t                     previous_actual_valid;
    uint8_t                     group_order;
    uint8_t                     include_subgroup_header;
    uint8_t                     has_object;
    uint8_t                     header_complete;
    uint8_t                     subgroup_id_mode;
    uint8_t                     properties_present;
    uint8_t                     default_priority;
    uint8_t                     first_object;
    uint8_t                     end_of_group;
    uint8_t                     fin_received;
    uint64_t                    properties_received;
    uint64_t                    payload_received;
} xqc_moq_d18_data_msg_t;

xqc_moq_d18_data_msg_t *xqc_moq_d18_data_msg_create(void);
void xqc_moq_d18_data_msg_destroy(void *msg);

void xqc_moq_d18_subgroup_header_init(xqc_moq_msg_base_t *base);
void xqc_moq_d18_subgroup_object_init(xqc_moq_msg_base_t *base);
void xqc_moq_d18_fetch_object_init(xqc_moq_msg_base_t *base);

void xqc_moq_d18_data_msg_set_previous(xqc_moq_d18_data_msg_t *msg,
    uint64_t group_id, uint64_t object_id, uint64_t subgroup_id,
    uint8_t priority, uint8_t valid);
void xqc_moq_d18_data_msg_inherit_subgroup(
    xqc_moq_d18_data_msg_t *msg,
    const xqc_moq_d18_data_msg_t *header);

xqc_int_t xqc_moq_d18_prepare_subgroup_message(
    xqc_moq_d18_data_msg_t *msg, const xqc_moq_object_t *object,
    uint8_t include_header);
xqc_int_t xqc_moq_d18_prepare_fetch_object(
    xqc_moq_d18_data_msg_t *msg, const xqc_moq_object_t *object);
xqc_int_t xqc_moq_d18_prepare_fetch_range(
    xqc_moq_d18_data_msg_t *msg, uint64_t group_id,
    uint64_t object_id, uint8_t unknown);

xqc_int_t xqc_moq_d18_object_datagram_encode(
    const xqc_moq_object_t *object, uint8_t *buf, size_t buf_cap);
xqc_int_t xqc_moq_d18_object_datagram_encode_len(
    const xqc_moq_object_t *object);
xqc_int_t xqc_moq_d18_object_datagram_decode(
    const uint8_t *buf, size_t buf_len, xqc_moq_object_t *object);
xqc_int_t xqc_moq_d18_decode_datagram(
    xqc_moq_session_t *session, const uint8_t *data, size_t data_len);
void xqc_moq_d18_object_free_fields(xqc_moq_object_t *object);

xqc_int_t xqc_moq_d18_on_subgroup_header(xqc_moq_session_t *session,
    xqc_moq_stream_t *stream, xqc_moq_d18_data_msg_t *msg);
xqc_bool_t xqc_moq_d18_subgroup_header_ready(
    const xqc_moq_d18_data_msg_t *msg);

uint8_t xqc_moq_d18_group_order_from_params(
    const xqc_moq_message_parameter_t *params, size_t params_num);

#endif /* _XQC_MOQ_D18_DATA_H_INCLUDED_ */
