#include "moq/moq_transport/draft18/xqc_moq_d18_update.h"

#include <limits.h>
#include <string.h>

#include "src/common/xqc_malloc.h"

static xqc_moq_d18_update_result_t
xqc_moq_d18_param_copy(const xqc_moq_message_parameter_t *src,
    xqc_moq_message_parameter_t *dst)
{
    if (src->length > SIZE_MAX
        || (src->length > 0 && src->value == NULL))
    {
        return XQC_MOQ_D18_UPDATE_INVALID_VALUE;
    }

    *dst = *src;
    dst->value = NULL;
    if (src->length > 0) {
        dst->value = xqc_malloc((size_t)src->length);
        if (dst->value == NULL) {
            return XQC_MOQ_D18_UPDATE_NO_MEMORY;
        }
        memcpy(dst->value, src->value, (size_t)src->length);
    }
    return XQC_MOQ_D18_UPDATE_OK;
}

void
xqc_moq_d18_params_free(xqc_moq_message_parameter_t *params, size_t count)
{
    if (params == NULL) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        xqc_free(params[i].value);
        params[i].value = NULL;
        params[i].length = 0;
    }
    xqc_free(params);
}

xqc_moq_d18_update_result_t
xqc_moq_d18_params_clone(const xqc_moq_message_parameter_t *src,
    size_t count, xqc_moq_message_parameter_t **dst)
{
    if (dst == NULL || (count > 0 && src == NULL)) {
        return XQC_MOQ_D18_UPDATE_INVALID_ARGUMENT;
    }
    *dst = NULL;
    if (count == 0) {
        return XQC_MOQ_D18_UPDATE_OK;
    }
    if (count > SIZE_MAX / sizeof(**dst)) {
        return XQC_MOQ_D18_UPDATE_NO_MEMORY;
    }

    xqc_moq_message_parameter_t *copy =
        xqc_calloc(count, sizeof(*copy));
    if (copy == NULL) {
        return XQC_MOQ_D18_UPDATE_NO_MEMORY;
    }
    for (size_t i = 0; i < count; i++) {
        xqc_moq_d18_update_result_t ret =
            xqc_moq_d18_param_copy(&src[i], &copy[i]);
        if (ret != XQC_MOQ_D18_UPDATE_OK) {
            xqc_moq_d18_params_free(copy, i + 1);
            return ret;
        }
    }
    *dst = copy;
    return XQC_MOQ_D18_UPDATE_OK;
}

static xqc_moq_d18_update_result_t
xqc_moq_d18_params_validate_sorted(
    const xqc_moq_message_parameter_t *params, size_t count)
{
    if (count > 0 && params == NULL) {
        return XQC_MOQ_D18_UPDATE_INVALID_ARGUMENT;
    }
    for (size_t i = 0; i < count; i++) {
        if (i > 0 && params[i].type < params[i - 1].type) {
            return XQC_MOQ_D18_UPDATE_INVALID_VALUE;
        }
        if (params[i].length > SIZE_MAX
            || (params[i].length > 0 && params[i].value == NULL))
        {
            return XQC_MOQ_D18_UPDATE_INVALID_VALUE;
        }
    }
    return XQC_MOQ_D18_UPDATE_OK;
}

static xqc_moq_d18_update_result_t
xqc_moq_d18_params_copy_group(
    const xqc_moq_message_parameter_t *source, size_t begin, size_t end,
    xqc_moq_message_parameter_t *merged, size_t *merged_count)
{
    for (size_t i = begin; i < end; i++) {
        xqc_moq_d18_update_result_t ret = xqc_moq_d18_param_copy(
            &source[i], &merged[*merged_count]);
        if (ret != XQC_MOQ_D18_UPDATE_OK) {
            return ret;
        }
        (*merged_count)++;
    }
    return XQC_MOQ_D18_UPDATE_OK;
}

static size_t
xqc_moq_d18_params_group_end(
    const xqc_moq_message_parameter_t *params, size_t count, size_t begin)
{
    size_t end = begin + 1;
    while (end < count && params[end].type == params[begin].type) {
        end++;
    }
    return end;
}

xqc_moq_d18_update_result_t
xqc_moq_d18_params_merge(
    const xqc_moq_message_parameter_t *current, size_t current_count,
    const xqc_moq_message_parameter_t *update, size_t update_count,
    xqc_moq_message_parameter_t **merged, size_t *merged_count)
{
    if (merged == NULL || merged_count == NULL) {
        return XQC_MOQ_D18_UPDATE_INVALID_ARGUMENT;
    }
    *merged = NULL;
    *merged_count = 0;
    if (current_count > SIZE_MAX / sizeof(**merged)
        || update_count > SIZE_MAX / sizeof(**merged)
        || current_count > SIZE_MAX - update_count)
    {
        return XQC_MOQ_D18_UPDATE_NO_MEMORY;
    }

    xqc_moq_d18_update_result_t ret =
        xqc_moq_d18_params_validate_sorted(current, current_count);
    if (ret != XQC_MOQ_D18_UPDATE_OK) {
        return ret;
    }
    ret = xqc_moq_d18_params_validate_sorted(update, update_count);
    if (ret != XQC_MOQ_D18_UPDATE_OK) {
        return ret;
    }

    size_t capacity = current_count + update_count;
    if (capacity == 0) {
        return XQC_MOQ_D18_UPDATE_OK;
    }
    xqc_moq_message_parameter_t *result =
        xqc_calloc(capacity, sizeof(*result));
    if (result == NULL) {
        return XQC_MOQ_D18_UPDATE_NO_MEMORY;
    }

    size_t current_index = 0;
    size_t update_index = 0;
    size_t result_count = 0;
    while (current_index < current_count || update_index < update_count) {
        if (update_index == update_count
            || (current_index < current_count
                && current[current_index].type < update[update_index].type))
        {
            size_t end = xqc_moq_d18_params_group_end(
                current, current_count, current_index);
            ret = xqc_moq_d18_params_copy_group(current, current_index, end,
                result, &result_count);
            current_index = end;

        } else {
            if (current_index < current_count
                && current[current_index].type == update[update_index].type)
            {
                current_index = xqc_moq_d18_params_group_end(
                    current, current_count, current_index);
            }
            size_t end = xqc_moq_d18_params_group_end(
                update, update_count, update_index);
            ret = xqc_moq_d18_params_copy_group(update, update_index, end,
                result, &result_count);
            update_index = end;
        }
        if (ret != XQC_MOQ_D18_UPDATE_OK) {
            xqc_moq_d18_params_free(result, result_count);
            return ret;
        }
    }

    *merged = result;
    *merged_count = result_count;
    return XQC_MOQ_D18_UPDATE_OK;
}

xqc_moq_d18_update_result_t
xqc_moq_d18_update_record_create(uint64_t request_id,
    const xqc_moq_message_parameter_t *params, size_t params_num,
    xqc_moq_d18_update_record_t **record)
{
    if (record == NULL) {
        return XQC_MOQ_D18_UPDATE_INVALID_ARGUMENT;
    }
    *record = NULL;
    xqc_moq_d18_update_record_t *created =
        xqc_calloc(1, sizeof(*created));
    if (created == NULL) {
        return XQC_MOQ_D18_UPDATE_NO_MEMORY;
    }
    xqc_init_list_head(&created->list_member);
    created->ref_count = 1;
    created->request_id = request_id;
    xqc_moq_d18_update_result_t ret = xqc_moq_d18_params_clone(
        params, params_num, &created->params);
    if (ret != XQC_MOQ_D18_UPDATE_OK) {
        xqc_free(created);
        return ret;
    }
    created->params_num = params_num;
    created->callback_view.request_id = request_id;
    created->callback_view.params_num = params_num;
    created->callback_view.params = created->params;
    *record = created;
    return XQC_MOQ_D18_UPDATE_OK;
}

void
xqc_moq_d18_update_record_retain(xqc_moq_d18_update_record_t *record)
{
    if (record != NULL) {
        record->ref_count++;
    }
}

void
xqc_moq_d18_update_record_release(xqc_moq_d18_update_record_t *record)
{
    if (record == NULL) {
        return;
    }
    if (record->ref_count == 0 || --record->ref_count != 0) {
        return;
    }
    for (size_t i = 0;
         i < record->callback_view.request_auth.count; i++)
    {
        xqc_free(record->callback_view.request_auth.tokens[i].token_value);
    }
    xqc_free(record->callback_view.request_auth.tokens);
    record->callback_view.request_auth.tokens = NULL;
    record->callback_view.request_auth.count = 0;
    xqc_moq_d18_params_free(record->params, (size_t)record->params_num);
    record->params = NULL;
    record->params_num = 0;
    record->callback_view.params = NULL;
    record->callback_view.params_num = 0;
    xqc_moq_namespace_prefix_destroy(record->candidate_prefix);
    record->candidate_prefix = NULL;
    xqc_free(record);
}

void
xqc_moq_d18_update_record_destroy(xqc_moq_d18_update_record_t *record)
{
    if (record == NULL) {
        return;
    }
    if (xqc_list_is_inited(&record->list_member)
        && !xqc_list_empty(&record->list_member))
    {
        xqc_list_del_init(&record->list_member);
    }
    xqc_moq_d18_update_record_release(record);
}

void
xqc_moq_d18_update_queue_init(xqc_list_head_t *queue)
{
    if (queue != NULL) {
        xqc_init_list_head(queue);
    }
}

xqc_moq_d18_update_result_t
xqc_moq_d18_update_queue_push(xqc_list_head_t *queue,
    xqc_moq_d18_update_record_t *record)
{
    if (queue == NULL || record == NULL || !xqc_list_is_inited(queue)
        || !xqc_list_is_inited(&record->list_member)
        || !xqc_list_empty(&record->list_member))
    {
        return XQC_MOQ_D18_UPDATE_INVALID_ARGUMENT;
    }
    xqc_list_add_tail(&record->list_member, queue);
    return XQC_MOQ_D18_UPDATE_OK;
}

xqc_moq_d18_update_record_t *
xqc_moq_d18_update_queue_peek(xqc_list_head_t *queue)
{
    if (queue == NULL || !xqc_list_is_inited(queue)
        || xqc_list_empty(queue))
    {
        return NULL;
    }
    return xqc_list_entry(queue->next,
        xqc_moq_d18_update_record_t, list_member);
}

xqc_moq_d18_update_record_t *
xqc_moq_d18_update_queue_pop(xqc_list_head_t *queue)
{
    xqc_moq_d18_update_record_t *record =
        xqc_moq_d18_update_queue_peek(queue);
    if (record != NULL) {
        xqc_list_del_init(&record->list_member);
    }
    return record;
}

void
xqc_moq_d18_update_queue_destroy(xqc_list_head_t *queue)
{
    if (queue == NULL) {
        return;
    }
    if (!xqc_list_is_inited(queue)) {
        xqc_init_list_head(queue);
        return;
    }
    xqc_moq_d18_update_record_t *record;
    while ((record = xqc_moq_d18_update_queue_pop(queue)) != NULL) {
        xqc_moq_d18_update_record_destroy(record);
    }
    xqc_init_list_head(queue);
}
