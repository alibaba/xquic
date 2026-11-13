/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>

#include "xqc_moq_test.h"
#include "moq/moq_transport/xqc_moq_message.h"

/*
 * Decode a whole message from buf the way a MoQ stream does, and free it:
 * return what the decoder returned.
 */
static xqc_int_t
xqc_test_moq_decode(xqc_moq_msg_type_t type, uint8_t *buf, size_t len,
                    xqc_int_t *finish)
{
    xqc_moq_decode_msg_ctx_t ctx;
    xqc_moq_msg_base_t *msg;
    xqc_int_t wait_more_data = 0, ret;

    xqc_moq_decode_msg_ctx_reset(&ctx);
    msg = xqc_moq_msg_create(type);
    CU_ASSERT_FATAL(msg != NULL);

    ret = msg->decode(buf, len, 1, &ctx, msg, finish, &wait_more_data);

    xqc_moq_msg_free(type, msg);
    return ret;
}

/* a CLIENT_SETUP and a SUBSCRIBE_UPDATE with one parameter decode whole */
void
xqc_test_moq_msg_params_decoded(void)
{
    /* one version, then one parameter: type 0, length 1, value 2 */
    uint8_t client_setup[] = {0x01, 0x01, 0x01, 0x00, 0x01, 0x02};
    /* ID and the four group and object fields, then the same parameter */
    uint8_t subscribe_update[] = {0x07, 0x01, 0x02, 0x03, 0x04,
                                  0x01, 0x00, 0x01, 0x02};
    xqc_int_t finish = 0;

    CU_ASSERT(xqc_test_moq_decode(XQC_MOQ_MSG_CLIENT_SETUP, client_setup,
                                  sizeof(client_setup), &finish)
              == sizeof(client_setup));
    CU_ASSERT(finish == 1);

    finish = 0;
    CU_ASSERT(xqc_test_moq_decode(XQC_MOQ_MSG_SUBSCRIBE_UPDATE,
                                  subscribe_update, sizeof(subscribe_update),
                                  &finish)
              == sizeof(subscribe_update));
    CU_ASSERT(finish == 1);
}

/*
 * A Number of Parameters above XQC_MOQ_MAX_PARAMS is refused before the
 * parameters are allocated, and freeing the message that the peer sent
 * must not walk parameters that do not exist.
 */
void
xqc_test_moq_msg_params_over_limit(void)
{
    uint8_t client_setup[] = {0x01, 0x01, XQC_MOQ_MAX_PARAMS + 1};
    uint8_t server_setup[] = {0x01, 0x3f};
    uint8_t subscribe_update[] = {0x07, 0x01, 0x02,
                                  0x03, 0x04, XQC_MOQ_MAX_PARAMS + 1};
    xqc_int_t finish = 0;

    CU_ASSERT(xqc_test_moq_decode(XQC_MOQ_MSG_CLIENT_SETUP, client_setup,
                                  sizeof(client_setup), &finish)
              == -XQC_ELIMIT);
    CU_ASSERT(xqc_test_moq_decode(XQC_MOQ_MSG_SERVER_SETUP, server_setup,
                                  sizeof(server_setup), &finish)
              == -XQC_ELIMIT);
    CU_ASSERT(xqc_test_moq_decode(XQC_MOQ_MSG_SUBSCRIBE_UPDATE,
                                  subscribe_update, sizeof(subscribe_update),
                                  &finish)
              == -XQC_ELIMIT);
    CU_ASSERT(finish == 0);
}

/*
 * Decode a message given in two parts, as a stream may deliver it: the
 * decoder waits for more data after the first part. Return the message,
 * which the caller frees.
 */
static xqc_moq_msg_base_t *
xqc_test_moq_decode_split(xqc_moq_msg_type_t type, uint8_t *first,
                          size_t first_len, uint8_t *second, size_t second_len,
                          xqc_int_t *finish)
{
    xqc_moq_decode_msg_ctx_t ctx;
    xqc_moq_msg_base_t *msg;
    xqc_int_t wait_more_data = 0, ret;

    xqc_moq_decode_msg_ctx_reset(&ctx);
    msg = xqc_moq_msg_create(type);
    CU_ASSERT_FATAL(msg != NULL);

    ret = msg->decode(first, first_len, 0, &ctx, msg, finish, &wait_more_data);
    CU_ASSERT(ret == first_len && wait_more_data == 1 && *finish == 0);

    wait_more_data = 0;
    ret = msg->decode(second, second_len, 0, &ctx, msg, finish,
                      &wait_more_data);
    CU_ASSERT(ret > 0);
    return msg;
}

/*
 * The Track Namespace and Track Name of a SUBSCRIBE read whole when the
 * stream splits them after their length.
 */
void
xqc_test_moq_msg_strings_split(void)
{
    /* ID 1, alias 2, namespace "ns", name "nm", LatestGroup, no parameter */
    uint8_t first[] = {0x01, 0x02, 0x02};
    uint8_t second[] = {'n', 's', 0x02, 'n', 'm', 0x01, 0x00};
    xqc_moq_subscribe_msg_t *subscribe;
    xqc_int_t finish = 0;

    subscribe = (xqc_moq_subscribe_msg_t *)
        xqc_test_moq_decode_split(XQC_MOQ_MSG_SUBSCRIBE, first, sizeof(first),
                                  second, sizeof(second), &finish);
    CU_ASSERT(finish == 1);
    CU_ASSERT(subscribe->track_namespace_len == 2
              && memcmp(subscribe->track_namespace, "ns", 2) == 0);
    CU_ASSERT(subscribe->track_name_len == 2
              && memcmp(subscribe->track_name, "nm", 2) == 0);
    xqc_moq_msg_free(XQC_MOQ_MSG_SUBSCRIBE, subscribe);
}

/*
 * An empty string split from what follows it keeps its length of zero:
 * the bytes after it are the next fields, not its length.
 */
void
xqc_test_moq_msg_empty_string_split(void)
{
    /* SUBSCRIBE: ID 1, alias 2, empty namespace | name "nm", LatestGroup */
    uint8_t sub_first[] = {0x01, 0x02, 0x00};
    uint8_t sub_second[] = {0x02, 'n', 'm', 0x01, 0x00};
    /* SUBSCRIBE_ERROR: ID 1, code 2, empty reason | alias 7 */
    uint8_t err_first[] = {0x01, 0x02, 0x00};
    uint8_t err_second[] = {0x07, 0x09};
    xqc_moq_subscribe_msg_t *subscribe;
    xqc_moq_subscribe_error_msg_t *subscribe_error;
    xqc_int_t finish = 0;

    subscribe = (xqc_moq_subscribe_msg_t *)
        xqc_test_moq_decode_split(XQC_MOQ_MSG_SUBSCRIBE, sub_first,
                                  sizeof(sub_first), sub_second,
                                  sizeof(sub_second), &finish);
    CU_ASSERT(finish == 1);
    CU_ASSERT(subscribe->track_namespace_len == 0);
    CU_ASSERT(subscribe->track_name_len == 2
              && memcmp(subscribe->track_name, "nm", 2) == 0);
    xqc_moq_msg_free(XQC_MOQ_MSG_SUBSCRIBE, subscribe);

    finish = 0;
    subscribe_error = (xqc_moq_subscribe_error_msg_t *)
        xqc_test_moq_decode_split(XQC_MOQ_MSG_SUBSCRIBE_ERROR, err_first,
                                  sizeof(err_first), err_second,
                                  sizeof(err_second), &finish);
    CU_ASSERT(finish == 1);
    CU_ASSERT(subscribe_error->reason_phrase_len == 0);
    CU_ASSERT(subscribe_error->track_alias == 7);
    xqc_moq_msg_free(XQC_MOQ_MSG_SUBSCRIBE_ERROR, subscribe_error);
}
