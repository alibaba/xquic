#ifndef _XQC_MOQ_D18_REQUEST_H_INCLUDED_
#define _XQC_MOQ_D18_REQUEST_H_INCLUDED_

#include <stdint.h>

#include "src/common/xqc_list.h"
#include "moq/moq_transport/draft18/xqc_moq_d18_defs.h"

typedef enum {
    XQC_MOQ_D18_REQUEST_ID_OK = 0,
    XQC_MOQ_D18_REQUEST_ID_INVALID_PARITY = -1,
    XQC_MOQ_D18_REQUEST_ID_DUPLICATE = -2,
    XQC_MOQ_D18_REQUEST_ID_NO_MEMORY = -3,
} xqc_moq_d18_request_id_result_t;

typedef struct {
    xqc_list_head_t  peer_ids;
    xqc_list_head_t  local_ids;
    uint64_t         next_local_id;
    uint8_t          local_is_server;
} xqc_moq_d18_request_registry_t;

void xqc_moq_d18_request_registry_init(
    xqc_moq_d18_request_registry_t *registry, uint8_t local_is_server);

void xqc_moq_d18_request_registry_destroy(
    xqc_moq_d18_request_registry_t *registry);

uint64_t xqc_moq_d18_request_id_allocate(
    xqc_moq_d18_request_registry_t *registry);

xqc_moq_d18_request_id_result_t xqc_moq_d18_request_id_validate_local(
    const xqc_moq_d18_request_registry_t *registry, uint64_t request_id);

xqc_moq_d18_request_id_result_t xqc_moq_d18_request_id_register_local(
    xqc_moq_d18_request_registry_t *registry, uint64_t request_id);

xqc_moq_d18_request_id_result_t xqc_moq_d18_request_id_register_peer(
    xqc_moq_d18_request_registry_t *registry, uint64_t request_id);

uint64_t xqc_moq_d18_request_id_error_code(
    xqc_moq_d18_request_id_result_t result);

#endif /* _XQC_MOQ_D18_REQUEST_H_INCLUDED_ */
