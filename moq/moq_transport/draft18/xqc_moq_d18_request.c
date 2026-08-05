#include "src/common/xqc_malloc.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_request.h"

typedef struct {
    xqc_list_head_t  list_member;
    uint64_t         request_id;
} xqc_moq_d18_request_id_entry_t;

void
xqc_moq_d18_request_registry_init(
    xqc_moq_d18_request_registry_t *registry, uint8_t local_is_server)
{
    xqc_init_list_head(&registry->peer_ids);
    xqc_init_list_head(&registry->local_ids);
    registry->local_is_server = local_is_server ? 1 : 0;
    registry->next_local_id = registry->local_is_server ? 1 : 0;
}

static void
xqc_moq_d18_request_id_list_destroy(xqc_list_head_t *list)
{
    xqc_list_head_t *pos;
    xqc_list_head_t *next;

    xqc_list_for_each_safe(pos, next, list) {
        xqc_moq_d18_request_id_entry_t *entry =
            xqc_list_entry(pos, xqc_moq_d18_request_id_entry_t,
                           list_member);
        xqc_list_del_init(&entry->list_member);
        xqc_free(entry);
    }
}

void
xqc_moq_d18_request_registry_destroy(
    xqc_moq_d18_request_registry_t *registry)
{
    xqc_moq_d18_request_id_list_destroy(
        &registry->peer_ids);
    xqc_moq_d18_request_id_list_destroy(
        &registry->local_ids);
}

uint64_t
xqc_moq_d18_request_id_allocate(
    xqc_moq_d18_request_registry_t *registry)
{
    uint64_t request_id = registry->next_local_id;
    registry->next_local_id += 2;
    return request_id;
}

static xqc_moq_d18_request_id_result_t
xqc_moq_d18_request_id_add(
    xqc_list_head_t *ids, uint64_t request_id)
{
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, ids) {
        xqc_moq_d18_request_id_entry_t *entry =
            xqc_list_entry(pos, xqc_moq_d18_request_id_entry_t,
                           list_member);
        if (entry->request_id == request_id) {
            return XQC_MOQ_D18_REQUEST_ID_DUPLICATE;
        }
    }

    xqc_moq_d18_request_id_entry_t *entry =
        xqc_malloc(sizeof(*entry));
    if (entry == NULL) {
        return XQC_MOQ_D18_REQUEST_ID_NO_MEMORY;
    }

    entry->request_id = request_id;
    xqc_init_list_head(&entry->list_member);
    xqc_list_add_tail(&entry->list_member, ids);
    return XQC_MOQ_D18_REQUEST_ID_OK;
}

static int
xqc_moq_d18_request_id_contains(
    const xqc_list_head_t *ids, uint64_t request_id)
{
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, ids) {
        const xqc_moq_d18_request_id_entry_t *entry =
            xqc_list_entry(pos, xqc_moq_d18_request_id_entry_t,
                           list_member);
        if (entry->request_id == request_id) {
            return 1;
        }
    }
    return 0;
}

xqc_moq_d18_request_id_result_t
xqc_moq_d18_request_id_validate_local(
    const xqc_moq_d18_request_registry_t *registry, uint64_t request_id)
{
    if (registry == NULL) {
        return XQC_MOQ_D18_REQUEST_ID_INVALID_PARITY;
    }
    uint64_t local_parity = registry->local_is_server ? 1 : 0;
    if ((request_id & 1) != local_parity) {
        return XQC_MOQ_D18_REQUEST_ID_INVALID_PARITY;
    }
    return xqc_moq_d18_request_id_contains(
               &registry->local_ids, request_id)
        ? XQC_MOQ_D18_REQUEST_ID_DUPLICATE
        : XQC_MOQ_D18_REQUEST_ID_OK;
}

xqc_moq_d18_request_id_result_t
xqc_moq_d18_request_id_register_local(
    xqc_moq_d18_request_registry_t *registry, uint64_t request_id)
{
    xqc_moq_d18_request_id_result_t validate_ret =
        xqc_moq_d18_request_id_validate_local(registry, request_id);
    if (validate_ret != XQC_MOQ_D18_REQUEST_ID_OK) {
        return validate_ret;
    }

    xqc_moq_d18_request_id_result_t ret =
        xqc_moq_d18_request_id_add(
            &registry->local_ids, request_id);
    if (ret != XQC_MOQ_D18_REQUEST_ID_OK) {
        return ret;
    }

    if (request_id >= registry->next_local_id) {
        registry->next_local_id = request_id + 2;
    }
    return XQC_MOQ_D18_REQUEST_ID_OK;
}

xqc_moq_d18_request_id_result_t
xqc_moq_d18_request_id_unregister_local(
    xqc_moq_d18_request_registry_t *registry, uint64_t request_id)
{
    if (registry == NULL) {
        return XQC_MOQ_D18_REQUEST_ID_INVALID_PARITY;
    }
    xqc_list_head_t *pos;
    xqc_list_head_t *next;
    xqc_list_for_each_safe(pos, next, &registry->local_ids) {
        xqc_moq_d18_request_id_entry_t *entry =
            xqc_list_entry(pos, xqc_moq_d18_request_id_entry_t,
                           list_member);
        if (entry->request_id == request_id) {
            xqc_list_del_init(&entry->list_member);
            xqc_free(entry);
            return XQC_MOQ_D18_REQUEST_ID_OK;
        }
    }
    return XQC_MOQ_D18_REQUEST_ID_DUPLICATE;
}

xqc_moq_d18_request_id_result_t
xqc_moq_d18_request_id_register_peer(
    xqc_moq_d18_request_registry_t *registry, uint64_t request_id)
{
    uint64_t peer_parity = registry->local_is_server ? 0 : 1;
    if ((request_id & 1) != peer_parity) {
        return XQC_MOQ_D18_REQUEST_ID_INVALID_PARITY;
    }

    return xqc_moq_d18_request_id_add(
        &registry->peer_ids, request_id);
}

uint64_t
xqc_moq_d18_request_id_error_code(
    xqc_moq_d18_request_id_result_t result)
{
    if (result == XQC_MOQ_D18_REQUEST_ID_INVALID_PARITY
        || result == XQC_MOQ_D18_REQUEST_ID_DUPLICATE)
    {
        return XQC_MOQ_D18_INVALID_REQUEST_ID;
    }

    if (result == XQC_MOQ_D18_REQUEST_ID_NO_MEMORY) {
        return XQC_MOQ_D18_INTERNAL_ERROR;
    }

    return XQC_MOQ_D18_NO_ERROR;
}
