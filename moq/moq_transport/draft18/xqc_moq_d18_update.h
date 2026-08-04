#ifndef _XQC_MOQ_D18_UPDATE_H_INCLUDED_
#define _XQC_MOQ_D18_UPDATE_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

#include "moq/xqc_moq.h"
#include "moq/moq_transport/xqc_moq_namespace.h"
#include "src/common/xqc_list.h"

typedef enum {
    XQC_MOQ_D18_UPDATE_OK = 0,
    XQC_MOQ_D18_UPDATE_INVALID_ARGUMENT = -1,
    XQC_MOQ_D18_UPDATE_INVALID_VALUE = -2,
    XQC_MOQ_D18_UPDATE_NO_MEMORY = -3,
} xqc_moq_d18_update_result_t;

typedef struct xqc_moq_d18_update_record_s {
    xqc_list_head_t             list_member;
    size_t                      ref_count;
    uint64_t                    request_id;
    uint64_t                    params_num;
    xqc_moq_message_parameter_t *params;
    xqc_moq_namespace_prefix_t  *candidate_prefix;
    xqc_moq_request_update_msg_t callback_view;
} xqc_moq_d18_update_record_t;

xqc_moq_d18_update_result_t xqc_moq_d18_params_clone(
    const xqc_moq_message_parameter_t *src, size_t count,
    xqc_moq_message_parameter_t **dst);

void xqc_moq_d18_params_free(
    xqc_moq_message_parameter_t *params, size_t count);

xqc_moq_d18_update_result_t xqc_moq_d18_params_merge(
    const xqc_moq_message_parameter_t *current, size_t current_count,
    const xqc_moq_message_parameter_t *update, size_t update_count,
    xqc_moq_message_parameter_t **merged, size_t *merged_count);

xqc_moq_d18_update_result_t xqc_moq_d18_update_record_create(
    uint64_t request_id, const xqc_moq_message_parameter_t *params,
    size_t params_num, xqc_moq_d18_update_record_t **record);

void xqc_moq_d18_update_record_destroy(
    xqc_moq_d18_update_record_t *record);

void xqc_moq_d18_update_record_retain(
    xqc_moq_d18_update_record_t *record);

void xqc_moq_d18_update_record_release(
    xqc_moq_d18_update_record_t *record);

void xqc_moq_d18_update_queue_init(xqc_list_head_t *queue);

xqc_moq_d18_update_result_t xqc_moq_d18_update_queue_push(
    xqc_list_head_t *queue, xqc_moq_d18_update_record_t *record);

xqc_moq_d18_update_record_t *xqc_moq_d18_update_queue_peek(
    xqc_list_head_t *queue);

xqc_moq_d18_update_record_t *xqc_moq_d18_update_queue_pop(
    xqc_list_head_t *queue);

void xqc_moq_d18_update_queue_destroy(xqc_list_head_t *queue);

#endif /* _XQC_MOQ_D18_UPDATE_H_INCLUDED_ */
