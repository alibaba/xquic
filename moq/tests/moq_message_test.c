#include <stdio.h>
#include <stdlib.h>

#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/common/xqc_malloc.h"
#include "moq/moq_transport/xqc_moq_message.h"

#define XQC_TEST_ASSERT(expr) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "assert failed: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
            return -1; \
        } \
    } while (0)

static int
xqc_test_publish_done_empty_reason_finishes(void)
{
    uint8_t buf[16] = {0};
    xqc_moq_publish_done_msg_t publish_done = {0};
    xqc_moq_decode_msg_ctx_t msg_ctx = {0};
    xqc_int_t finish = 0;
    xqc_int_t wait_more_data = 0;
    xqc_int_t ret = 0;
    uint8_t *p = buf;

    *p++ = 0;
    *p++ = 4;
    p = xqc_put_varint(p, 1);
    p = xqc_put_varint(p, 2);
    p = xqc_put_varint(p, 3);
    p = xqc_put_varint(p, 0);

    xqc_moq_msg_publish_done_init_handler(&publish_done.msg_base);

    ret = xqc_moq_msg_decode_publish_done(buf, p - buf, 0, &msg_ctx, &publish_done.msg_base,
                                          &finish, &wait_more_data);

    XQC_TEST_ASSERT(ret == p - buf);
    XQC_TEST_ASSERT(finish == 1);
    XQC_TEST_ASSERT(wait_more_data == 0);
    XQC_TEST_ASSERT(publish_done.subscribe_id == 1);
    XQC_TEST_ASSERT(publish_done.status_code == 2);
    XQC_TEST_ASSERT(publish_done.stream_count == 3);
    XQC_TEST_ASSERT(publish_done.reason_phrase_len == 0);

    xqc_free(publish_done.reason_phrase);
    return 0;
}

int
main(void)
{
    if (xqc_test_publish_done_empty_reason_finishes() != 0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
