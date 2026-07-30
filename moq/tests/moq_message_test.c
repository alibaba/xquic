#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "src/common/utils/vint/xqc_variable_len_int.h"
#include "src/common/xqc_malloc.h"
#include "moq/moq_transport/xqc_moq_message.h"
#include "moq/moq_transport/xqc_moq_session.h"

#define XQC_TEST_ASSERT(expr) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "assert failed: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
            return -1; \
        } \
    } while (0)

static int
xqc_test_setup_roundtrip(void)
{
    static const uint8_t expected_options[] = {
        0x01, 0x01, '/',
        0x04, 0x09, 'r', 'e', 'l', 'a', 'y', ':', '4', '4', '3',
    };
    static const uint8_t expected_prefix[] = {0xaf, 0x00, 0x00, 0x0e};
    uint8_t buf[64] = {0};
    xqc_moq_setup_msg_t setup = {0};
    xqc_moq_setup_msg_t decoded = {0};
    xqc_moq_decode_msg_ctx_t msg_ctx = {0};
    xqc_moq_msg_type_t type = 0;
    xqc_int_t finish = 0;
    xqc_int_t wait_more_data = 0;

    xqc_moq_msg_setup_init_handler(&setup.msg_base);
    setup.options = (uint8_t *)expected_options;
    setup.options_len = sizeof(expected_options);
    xqc_int_t len = xqc_moq_msg_encode_setup_len(&setup.msg_base);
    XQC_TEST_ASSERT(len == 18);
    XQC_TEST_ASSERT(xqc_moq_msg_encode_setup(&setup.msg_base, buf, sizeof(buf)) == len);
    XQC_TEST_ASSERT(memcmp(buf, expected_prefix, sizeof(expected_prefix)) == 0);
    XQC_TEST_ASSERT(memcmp(buf + sizeof(expected_prefix), expected_options,
                           sizeof(expected_options)) == 0);

    xqc_int_t type_len = xqc_moq_msg_decode_type_vi64(buf, len, &type, &wait_more_data);
    XQC_TEST_ASSERT(type_len == 2);
    XQC_TEST_ASSERT(type == XQC_MOQ_MSG_SETUP);
    XQC_TEST_ASSERT(wait_more_data == 0);

    xqc_moq_msg_setup_init_handler(&decoded.msg_base);
    XQC_TEST_ASSERT(xqc_moq_msg_decode_setup(buf + type_len, len - type_len, 0,
        &msg_ctx, &decoded.msg_base, &finish, &wait_more_data) == len - type_len);
    XQC_TEST_ASSERT(finish == 1);
    XQC_TEST_ASSERT(wait_more_data == 0);
    XQC_TEST_ASSERT(decoded.options_len == sizeof(expected_options));
    XQC_TEST_ASSERT(memcmp(decoded.options, expected_options, sizeof(expected_options)) == 0);

    xqc_free(decoded.options);
    return 0;
}

static int
xqc_test_setup_empty_options(void)
{
    static const uint8_t encoded[] = {0xaf, 0x00, 0x00, 0x00};
    xqc_moq_setup_msg_t decoded = {0};
    xqc_moq_decode_msg_ctx_t msg_ctx = {0};
    xqc_int_t finish = 0;
    xqc_int_t wait_more_data = 0;

    xqc_moq_msg_setup_init_handler(&decoded.msg_base);
    XQC_TEST_ASSERT(xqc_moq_msg_decode_setup((uint8_t *)encoded + 2, 2, 0,
        &msg_ctx, &decoded.msg_base, &finish, &wait_more_data) == 2);
    XQC_TEST_ASSERT(finish == 1);
    XQC_TEST_ASSERT(wait_more_data == 0);
    XQC_TEST_ASSERT(decoded.options_len == 0);
    XQC_TEST_ASSERT(decoded.options == NULL);
    return 0;
}

static int
xqc_test_publish_namespace_vi64_encoding(void)
{
    static const uint8_t expected[] = {
        0x06, 0x00, 0x14, 0x00, 0x01, 0x10,
        'm', 'o', 'q', '-', 't', 'e', 's', 't',
        '/', 'i', 'n', 't', 'e', 'r', 'o', 'p',
        0x00,
    };
    xqc_moq_track_ns_field_t ns = {
        .len = sizeof("moq-test/interop") - 1,
        .data = (unsigned char *)"moq-test/interop",
    };
    xqc_moq_publish_namespace_msg_t msg = {0};
    uint8_t buf[64] = {0};

    xqc_moq_msg_publish_namespace_vi64_init_handler(&msg.msg_base);
    msg.request_id = 0;
    msg.track_namespace_num = 1;
    msg.track_namespace_tuple = &ns;

    xqc_int_t len = xqc_moq_msg_encode_publish_namespace_len_vi64(&msg.msg_base);
    XQC_TEST_ASSERT(len == sizeof(expected));
    XQC_TEST_ASSERT(xqc_moq_msg_encode_publish_namespace_vi64(
        &msg.msg_base, buf, sizeof(buf)) == len);
    XQC_TEST_ASSERT(memcmp(buf, expected, sizeof(expected)) == 0);
    return 0;
}

static int
xqc_test_request_ok_vi64_decoding(void)
{
    static const uint8_t encoded[] = {0x07, 0x00, 0x01, 0x00};
    xqc_moq_request_ok_msg_t msg = {0};
    xqc_moq_decode_msg_ctx_t msg_ctx = {0};
    xqc_moq_msg_type_t type = 0;
    xqc_int_t finish = 0;
    xqc_int_t wait_more_data = 0;

    xqc_int_t type_len = xqc_moq_msg_decode_type_vi64((uint8_t *)encoded,
        sizeof(encoded), &type, &wait_more_data);
    XQC_TEST_ASSERT(type_len == 1);
    XQC_TEST_ASSERT(type == XQC_MOQ_MSG_REQUEST_OK);

    xqc_moq_msg_request_ok_init_handler(&msg.msg_base);
    XQC_TEST_ASSERT(xqc_moq_msg_decode_request_ok((uint8_t *)encoded + type_len,
        sizeof(encoded) - type_len, 0, &msg_ctx, &msg.msg_base,
        &finish, &wait_more_data) == sizeof(encoded) - type_len);
    XQC_TEST_ASSERT(finish == 1);
    XQC_TEST_ASSERT(wait_more_data == 0);
    XQC_TEST_ASSERT(msg.params_num == 0);
    return 0;
}

static int
xqc_test_subscribe_request_vi64_encoding(void)
{
    static const uint8_t expected[] = {
        0x03, 0x00, 0x24, 0x00, 0x01, 0x15,
        'n', 'o', 'n', 'e', 'x', 'i', 's', 't', 'e', 'n', 't',
        '/', 'n', 'a', 'm', 'e', 's', 'p', 'a', 'c', 'e',
        0x0a, 't', 'e', 's', 't', '-', 't', 'r', 'a', 'c', 'k',
        0x00,
    };
    xqc_moq_track_ns_field_t ns = {
        .len = sizeof("nonexistent/namespace") - 1,
        .data = (unsigned char *)"nonexistent/namespace",
    };
    xqc_moq_subscribe_msg_t msg = {0};
    uint8_t buf[64] = {0};

    xqc_moq_msg_subscribe_request_init_handler(&msg.msg_base);
    msg.subscribe_id = 0;
    msg.track_namespace_num = 1;
    msg.track_namespace_tuple = &ns;
    msg.track_name = "test-track";
    msg.track_name_len = sizeof("test-track") - 1;

    xqc_int_t len = xqc_moq_msg_encode_subscribe_request_len(&msg.msg_base);
    XQC_TEST_ASSERT(len == sizeof(expected));
    XQC_TEST_ASSERT(xqc_moq_msg_encode_subscribe_request(
        &msg.msg_base, buf, sizeof(buf)) == len);
    XQC_TEST_ASSERT(memcmp(buf, expected, sizeof(expected)) == 0);

    xqc_moq_subscribe_msg_t *decoded = xqc_moq_msg_create_subscribe();
    xqc_moq_decode_msg_ctx_t msg_ctx = {0};
    xqc_int_t finish = 0;
    xqc_int_t wait_more_data = 0;
    XQC_TEST_ASSERT(decoded != NULL);
    xqc_moq_msg_subscribe_request_init_handler(&decoded->msg_base);
    XQC_TEST_ASSERT(xqc_moq_msg_decode_subscribe_request(buf + 1, 8, 0,
        &msg_ctx, &decoded->msg_base, &finish, &wait_more_data) == 8);
    XQC_TEST_ASSERT(finish == 0);
    XQC_TEST_ASSERT(wait_more_data == 1);
    XQC_TEST_ASSERT(xqc_moq_msg_decode_subscribe_request(buf + 9, len - 9, 1,
        &msg_ctx, &decoded->msg_base, &finish, &wait_more_data) == len - 9);
    XQC_TEST_ASSERT(finish == 1);
    XQC_TEST_ASSERT(wait_more_data == 0);
    XQC_TEST_ASSERT(decoded->subscribe_id == 0);
    XQC_TEST_ASSERT(decoded->track_namespace_num == 1);
    XQC_TEST_ASSERT(decoded->track_namespace_tuple[0].len == ns.len);
    XQC_TEST_ASSERT(memcmp(decoded->track_namespace_tuple[0].data,
                           ns.data, ns.len) == 0);
    XQC_TEST_ASSERT(decoded->track_name_len == sizeof("test-track") - 1);
    XQC_TEST_ASSERT(memcmp(decoded->track_name, "test-track",
                           decoded->track_name_len) == 0);
    XQC_TEST_ASSERT(decoded->params_num == 0);
    xqc_moq_msg_free_subscribe(decoded);
    return 0;
}

static int
xqc_test_subscribe_ok_response_vi64_roundtrip(void)
{
    static const uint8_t expected[] = {0x04, 0x00, 0x02, 0x07, 0x00};
    xqc_moq_subscribe_ok_msg_t msg = {0};
    xqc_moq_subscribe_ok_msg_t *decoded = xqc_moq_msg_create_subscribe_ok();
    xqc_moq_decode_msg_ctx_t msg_ctx = {0};
    uint8_t buf[16] = {0};
    xqc_int_t finish = 0;
    xqc_int_t wait_more_data = 0;

    xqc_moq_msg_subscribe_ok_response_init_handler(&msg.msg_base);
    msg.track_alias = 7;
    xqc_int_t len = xqc_moq_msg_encode_subscribe_ok_response_len(&msg.msg_base);
    XQC_TEST_ASSERT(len == sizeof(expected));
    XQC_TEST_ASSERT(xqc_moq_msg_encode_subscribe_ok_response(
        &msg.msg_base, buf, sizeof(buf)) == len);
    XQC_TEST_ASSERT(memcmp(buf, expected, sizeof(expected)) == 0);

    XQC_TEST_ASSERT(decoded != NULL);
    xqc_moq_msg_subscribe_ok_response_init_handler(&decoded->msg_base);
    XQC_TEST_ASSERT(xqc_moq_msg_decode_subscribe_ok_response(buf + 1, 2, 0,
        &msg_ctx, &decoded->msg_base, &finish, &wait_more_data) == 2);
    XQC_TEST_ASSERT(finish == 0);
    XQC_TEST_ASSERT(wait_more_data == 1);
    XQC_TEST_ASSERT(xqc_moq_msg_decode_subscribe_ok_response(buf + 3, len - 3, 1,
        &msg_ctx, &decoded->msg_base, &finish, &wait_more_data) == len - 3);
    XQC_TEST_ASSERT(finish == 1);
    XQC_TEST_ASSERT(wait_more_data == 0);
    XQC_TEST_ASSERT(decoded->track_alias == 7);
    XQC_TEST_ASSERT(decoded->params_num == 0);
    XQC_TEST_ASSERT(decoded->track_properties_len == 0);
    xqc_moq_msg_free_subscribe_ok(decoded);
    return 0;
}

static int
xqc_test_request_error_fragmented_decoding(void)
{
    static const uint8_t expected[] = {
        0x05, 0x00, 0x0c, 0x10, 0x00, 0x09,
        'n', 'o', 't', ' ', 'f', 'o', 'u', 'n', 'd',
    };
    xqc_moq_request_error_msg_t encoded = {0};
    xqc_moq_request_error_msg_t decoded = {0};
    xqc_moq_decode_msg_ctx_t msg_ctx = {0};
    uint8_t buf[32] = {0};
    xqc_int_t finish = 0;
    xqc_int_t wait_more_data = 0;

    xqc_moq_msg_request_error_init_handler(&encoded.msg_base);
    encoded.error_code = XQC_MOQ_REQUEST_ERROR_DOES_NOT_EXIST;
    encoded.reason_phrase = "not found";
    encoded.reason_phrase_len = sizeof("not found") - 1;
    xqc_int_t len = xqc_moq_msg_encode_request_error_len(&encoded.msg_base);
    XQC_TEST_ASSERT(len == sizeof(expected));
    XQC_TEST_ASSERT(xqc_moq_msg_encode_request_error(
        &encoded.msg_base, buf, sizeof(buf)) == len);
    XQC_TEST_ASSERT(memcmp(buf, expected, sizeof(expected)) == 0);

    xqc_moq_msg_request_error_init_handler(&decoded.msg_base);
    XQC_TEST_ASSERT(xqc_moq_msg_decode_request_error(buf + 1, 4, 0,
        &msg_ctx, &decoded.msg_base, &finish, &wait_more_data) == 4);
    XQC_TEST_ASSERT(finish == 0);
    XQC_TEST_ASSERT(wait_more_data == 1);
    XQC_TEST_ASSERT(xqc_moq_msg_decode_request_error(buf + 5, len - 5, 1,
        &msg_ctx, &decoded.msg_base, &finish, &wait_more_data) == len - 5);
    XQC_TEST_ASSERT(finish == 1);
    XQC_TEST_ASSERT(wait_more_data == 0);
    XQC_TEST_ASSERT(decoded.error_code == XQC_MOQ_REQUEST_ERROR_DOES_NOT_EXIST);
    XQC_TEST_ASSERT(decoded.retry_interval == 0);
    XQC_TEST_ASSERT(decoded.reason_phrase_len == sizeof("not found") - 1);
    XQC_TEST_ASSERT(memcmp(decoded.reason_phrase, "not found",
                           decoded.reason_phrase_len) == 0);

    xqc_free(decoded.reason_phrase);
    xqc_free(decoded.redirect);
    xqc_free(decoded.payload);
    return 0;
}

static int
xqc_test_advertised_namespace_registry_lifecycle(void)
{
    xqc_moq_session_t session;
    xqc_memzero(&session, sizeof(session));
    xqc_init_list_head(&session.local_advertised_namespace_list);
    xqc_init_list_head(&session.peer_advertised_namespace_list);

    xqc_moq_track_ns_field_t ns[3] = {
        {.len = 2, .data = (unsigned char *)"aa"},
        {.len = 2, .data = (unsigned char *)"bb"},
        {.len = 2, .data = (unsigned char *)"cc"},
    };

    XQC_TEST_ASSERT(xqc_moq_session_find_advertised_namespace(&session, 1, ns, 3) == NULL);
    XQC_TEST_ASSERT(xqc_moq_session_add_advertised_namespace(&session, 1, ns, 3) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_session_find_advertised_namespace(&session, 1, ns, 3) != NULL);
    XQC_TEST_ASSERT(xqc_moq_session_add_advertised_namespace(&session, 1, ns, 3) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_session_bind_advertised_namespace_request(
        &session, 1, ns, 3, 42) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_session_find_advertised_namespace_by_request(
        &session, 1, 42) == xqc_moq_session_find_advertised_namespace(
            &session, 1, ns, 3));
    XQC_TEST_ASSERT(xqc_moq_session_remove_advertised_namespace(&session, 1, ns, 3) == 1);
    XQC_TEST_ASSERT(xqc_moq_session_find_advertised_namespace(&session, 1, ns, 3) == NULL);
    XQC_TEST_ASSERT(xqc_moq_session_remove_advertised_namespace(&session, 1, ns, 3) == 0);

    return 0;
}

static int
xqc_test_publish_namespace_done_request_id_decoding(void)
{
    static const uint8_t encoded[] = {0x00, 0x01, 0x2a};
    xqc_moq_publish_namespace_done_msg_t done = {0};
    xqc_moq_decode_msg_ctx_t msg_ctx = {0};
    xqc_int_t finish = 0;
    xqc_int_t wait_more_data = 0;

    xqc_moq_msg_publish_namespace_done_request_init_handler(&done.msg_base);
    XQC_TEST_ASSERT(xqc_moq_msg_decode_publish_namespace_done_request(
        (uint8_t *)encoded, sizeof(encoded), 0, &msg_ctx, &done.msg_base,
        &finish, &wait_more_data) == (xqc_int_t)sizeof(encoded));
    XQC_TEST_ASSERT(finish == 1);
    XQC_TEST_ASSERT(wait_more_data == 0);
    XQC_TEST_ASSERT(done.request_id == 42);
    return 0;
}

static void
xqc_test_init_namespace_session(xqc_moq_session_t *session)
{
    xqc_memzero(session, sizeof(*session));
    xqc_init_list_head(&session->local_advertised_namespace_list);
    xqc_init_list_head(&session->peer_advertised_namespace_list);
    xqc_init_list_head(&session->peer_subscribe_namespace_list);
    xqc_init_list_head(&session->track_list_for_pub);
}

static int
xqc_test_publish_namespace_rejects_oversized_tuple(void)
{
    xqc_moq_session_t session;
    xqc_test_init_namespace_session(&session);

    xqc_moq_track_ns_field_t ns[1] = {
        {.len = 2, .data = (unsigned char *)"aa"},
    };
    xqc_moq_publish_namespace_msg_t pub = {0};
    pub.track_namespace_tuple = ns;
    pub.track_namespace_num = XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS + 1;
    xqc_moq_publish_namespace_done_msg_t done = {0};
    done.track_namespace_tuple = ns;
    done.track_namespace_num = XQC_MOQ_MAX_NAMESPACE_TUPLE_ELEMS + 1;

    XQC_TEST_ASSERT(xqc_moq_publish_namespace(&session, &pub) == -XQC_EPARAM);
    XQC_TEST_ASSERT(xqc_moq_publish_namespace_done(&session, &done) == -XQC_EPARAM);
    XQC_TEST_ASSERT(xqc_list_empty(&session.local_advertised_namespace_list));

    return 0;
}

static int
xqc_test_namespace_root_done_and_parent_child_rules(void)
{
    xqc_moq_session_t session;
    xqc_test_init_namespace_session(&session);

    xqc_moq_track_ns_field_t ns_root[1] = {
        {.len = 2, .data = (unsigned char *)"aa"},
    };
    xqc_moq_track_ns_field_t ns_child[2] = {
        {.len = 2, .data = (unsigned char *)"aa"},
        {.len = 2, .data = (unsigned char *)"bb"},
    };
    xqc_moq_publish_namespace_msg_t pub_root = {0};
    pub_root.track_namespace_tuple = ns_root;
    pub_root.track_namespace_num = 1;
    xqc_moq_publish_namespace_done_msg_t done_root = {0};
    done_root.track_namespace_tuple = ns_root;
    done_root.track_namespace_num = 1;
    xqc_moq_publish_namespace_msg_t pub_child = {0};
    pub_child.track_namespace_tuple = ns_child;
    pub_child.track_namespace_num = 2;
    xqc_moq_publish_namespace_done_msg_t done_child = {0};
    done_child.track_namespace_tuple = ns_child;
    done_child.track_namespace_num = 2;

    XQC_TEST_ASSERT(xqc_moq_publish_namespace(&session, &pub_root) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_session_find_advertised_namespace(&session, 1, ns_root, 1) != NULL);
    XQC_TEST_ASSERT(xqc_moq_publish_namespace_done(&session, &done_root) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_session_find_advertised_namespace(&session, 1, ns_root, 1) == NULL);

    XQC_TEST_ASSERT(xqc_moq_publish_namespace(&session, &pub_child) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_publish_namespace_done(&session, &done_root) == -XQC_EPARAM);
    XQC_TEST_ASSERT(xqc_moq_session_find_advertised_namespace(&session, 1, ns_root, 1) != NULL);
    XQC_TEST_ASSERT(xqc_moq_session_find_advertised_namespace(&session, 1, ns_child, 2) != NULL);
    XQC_TEST_ASSERT(xqc_moq_publish_namespace_done(&session, &done_child) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_session_find_advertised_namespace(&session, 1, ns_child, 2) == NULL);
    XQC_TEST_ASSERT(xqc_moq_publish_namespace_done(&session, &done_root) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_session_find_advertised_namespace(&session, 1, ns_root, 1) == NULL);

    return 0;
}

static int
xqc_test_namespace_upgrade_keeps_parent(void)
{
    xqc_moq_session_t session;
    xqc_test_init_namespace_session(&session);

    xqc_moq_track_ns_field_t ns_child[3] = {
        {.len = 2, .data = (unsigned char *)"aa"},
        {.len = 2, .data = (unsigned char *)"bb"},
        {.len = 2, .data = (unsigned char *)"cc"},
    };
    xqc_moq_track_ns_field_t ns_parent[2] = {
        {.len = 2, .data = (unsigned char *)"aa"},
        {.len = 2, .data = (unsigned char *)"bb"},
    };
    xqc_moq_publish_namespace_msg_t pub_child = {0};
    pub_child.track_namespace_tuple = ns_child;
    pub_child.track_namespace_num = 3;
    xqc_moq_publish_namespace_msg_t pub_parent = {0};
    pub_parent.track_namespace_tuple = ns_parent;
    pub_parent.track_namespace_num = 2;
    xqc_moq_publish_namespace_done_msg_t done_child = {0};
    done_child.track_namespace_tuple = ns_child;
    done_child.track_namespace_num = 3;
    xqc_moq_publish_namespace_done_msg_t done_parent = {0};
    done_parent.track_namespace_tuple = ns_parent;
    done_parent.track_namespace_num = 2;

    XQC_TEST_ASSERT(xqc_moq_publish_namespace(&session, &pub_child) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_publish_namespace(&session, &pub_parent) == XQC_OK);

    xqc_moq_namespace_advertisement_t *aa =
        xqc_moq_session_find_advertised_namespace(&session, 1, ns_child, 1);
    xqc_moq_namespace_advertisement_t *aa_bb =
        xqc_moq_session_find_advertised_namespace(&session, 1, ns_child, 2);
    XQC_TEST_ASSERT(aa != NULL);
    XQC_TEST_ASSERT(aa_bb != NULL);
    XQC_TEST_ASSERT(aa->child_refcnt == 2);
    XQC_TEST_ASSERT(aa_bb->explicit_advertised == 1);

    XQC_TEST_ASSERT(xqc_moq_publish_namespace_done(&session, &done_child) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_session_find_advertised_namespace(&session, 1, ns_child, 3) == NULL);
    aa = xqc_moq_session_find_advertised_namespace(&session, 1, ns_child, 1);
    aa_bb = xqc_moq_session_find_advertised_namespace(&session, 1, ns_child, 2);
    XQC_TEST_ASSERT(aa != NULL);
    XQC_TEST_ASSERT(aa_bb != NULL);
    XQC_TEST_ASSERT(aa->child_refcnt == 1);
    XQC_TEST_ASSERT(aa_bb->explicit_advertised == 1);
    XQC_TEST_ASSERT(aa_bb->child_refcnt == 0);

    XQC_TEST_ASSERT(xqc_moq_publish_namespace_done(&session, &done_parent) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_session_find_advertised_namespace(&session, 1, ns_child, 1) != NULL);
    XQC_TEST_ASSERT(xqc_moq_session_find_advertised_namespace(&session, 1, ns_child, 2) == NULL);

    return 0;
}

static int
xqc_test_namespace_sibling_done_keeps_parent(void)
{
    xqc_moq_session_t session;
    xqc_test_init_namespace_session(&session);

    xqc_moq_track_ns_field_t ns_cc[3] = {
        {.len = 2, .data = (unsigned char *)"aa"},
        {.len = 2, .data = (unsigned char *)"bb"},
        {.len = 2, .data = (unsigned char *)"cc"},
    };
    xqc_moq_track_ns_field_t ns_dd[3] = {
        {.len = 2, .data = (unsigned char *)"aa"},
        {.len = 2, .data = (unsigned char *)"bb"},
        {.len = 2, .data = (unsigned char *)"dd"},
    };
    xqc_moq_publish_namespace_msg_t pub_cc = {0};
    pub_cc.track_namespace_tuple = ns_cc;
    pub_cc.track_namespace_num = 3;
    xqc_moq_publish_namespace_msg_t pub_dd = {0};
    pub_dd.track_namespace_tuple = ns_dd;
    pub_dd.track_namespace_num = 3;
    xqc_moq_publish_namespace_done_msg_t done_cc = {0};
    done_cc.track_namespace_tuple = ns_cc;
    done_cc.track_namespace_num = 3;
    xqc_moq_publish_namespace_done_msg_t done_dd = {0};
    done_dd.track_namespace_tuple = ns_dd;
    done_dd.track_namespace_num = 3;

    XQC_TEST_ASSERT(xqc_moq_publish_namespace(&session, &pub_cc) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_publish_namespace(&session, &pub_dd) == XQC_OK);

    xqc_moq_namespace_advertisement_t *aa =
        xqc_moq_session_find_advertised_namespace(&session, 1, ns_cc, 1);
    xqc_moq_namespace_advertisement_t *aa_bb =
        xqc_moq_session_find_advertised_namespace(&session, 1, ns_cc, 2);
    XQC_TEST_ASSERT(aa != NULL);
    XQC_TEST_ASSERT(aa_bb != NULL);
    XQC_TEST_ASSERT(aa->child_refcnt == 2);
    XQC_TEST_ASSERT(aa_bb->child_refcnt == 2);

    XQC_TEST_ASSERT(xqc_moq_publish_namespace_done(&session, &done_cc) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_session_find_advertised_namespace(&session, 1, ns_cc, 3) == NULL);
    XQC_TEST_ASSERT(xqc_moq_session_find_advertised_namespace(&session, 1, ns_dd, 3) != NULL);
    aa = xqc_moq_session_find_advertised_namespace(&session, 1, ns_cc, 1);
    aa_bb = xqc_moq_session_find_advertised_namespace(&session, 1, ns_cc, 2);
    XQC_TEST_ASSERT(aa != NULL);
    XQC_TEST_ASSERT(aa_bb != NULL);
    XQC_TEST_ASSERT(aa->child_refcnt == 1);
    XQC_TEST_ASSERT(aa_bb->child_refcnt == 1);

    XQC_TEST_ASSERT(xqc_moq_publish_namespace_done(&session, &done_dd) == XQC_OK);
    aa = xqc_moq_session_find_advertised_namespace(&session, 1, ns_cc, 1);
    aa_bb = xqc_moq_session_find_advertised_namespace(&session, 1, ns_cc, 2);
    XQC_TEST_ASSERT(aa != NULL);
    XQC_TEST_ASSERT(aa_bb != NULL);
    XQC_TEST_ASSERT(aa->child_refcnt == 0);
    XQC_TEST_ASSERT(aa_bb->child_refcnt == 0);
    XQC_TEST_ASSERT(xqc_moq_session_find_advertised_namespace(&session, 1, ns_dd, 3) == NULL);

    return 0;
}

static int
xqc_test_publish_namespace_roundtrip(void)
{
    xqc_moq_track_ns_field_t ns[3] = {
        {.len = 2, .data = (unsigned char *)"aa"},
        {.len = 2, .data = (unsigned char *)"bb"},
        {.len = 2, .data = (unsigned char *)"cc"},
    };
    xqc_moq_publish_namespace_msg_t publish_namespace = {0};
    xqc_moq_publish_namespace_msg_t decoded = {0};
    xqc_moq_decode_msg_ctx_t msg_ctx = {0};
    uint8_t buf[128] = {0};
    xqc_int_t finish = 0;
    xqc_int_t wait_more_data = 0;
    xqc_int_t len;
    xqc_int_t ret;

    xqc_moq_msg_publish_namespace_init_handler(&publish_namespace.msg_base);
    publish_namespace.request_id = 0;
    publish_namespace.track_namespace_num = 3;
    publish_namespace.track_namespace_tuple = ns;
    publish_namespace.params_num = 0;

    len = xqc_moq_msg_encode_publish_namespace_len(&publish_namespace.msg_base);
    XQC_TEST_ASSERT(len > 0);

    ret = xqc_moq_msg_encode_publish_namespace(&publish_namespace.msg_base, buf, sizeof(buf));
    XQC_TEST_ASSERT(ret == len);
    XQC_TEST_ASSERT(buf[0] == XQC_MOQ_MSG_PUBLISH_NAMESPACE);

    xqc_moq_msg_publish_namespace_init_handler(&decoded.msg_base);
    ret = xqc_moq_msg_decode_publish_namespace(buf + 1, ret - 1, 0, &msg_ctx, &decoded.msg_base,
                                               &finish, &wait_more_data);

    XQC_TEST_ASSERT(ret == len - 1);
    XQC_TEST_ASSERT(finish == 1);
    XQC_TEST_ASSERT(wait_more_data == 0);
    XQC_TEST_ASSERT(decoded.request_id == 0);
    XQC_TEST_ASSERT(decoded.track_namespace_num == 3);
    XQC_TEST_ASSERT(decoded.params_num == 0);
    XQC_TEST_ASSERT(decoded.track_namespace_tuple[0].len == 2);
    XQC_TEST_ASSERT(memcmp(decoded.track_namespace_tuple[0].data, "aa", 2) == 0);
    XQC_TEST_ASSERT(decoded.track_namespace_tuple[1].len == 2);
    XQC_TEST_ASSERT(memcmp(decoded.track_namespace_tuple[1].data, "bb", 2) == 0);
    XQC_TEST_ASSERT(decoded.track_namespace_tuple[2].len == 2);
    XQC_TEST_ASSERT(memcmp(decoded.track_namespace_tuple[2].data, "cc", 2) == 0);

    for (uint64_t i = 0; i < decoded.track_namespace_num; i++) {
        xqc_free(decoded.track_namespace_tuple[i].data);
    }
    xqc_free(decoded.track_namespace_tuple);
    return 0;
}

static int
xqc_test_publish_namespace_done_roundtrip(void)
{
    xqc_moq_track_ns_field_t ns[2] = {
        {.len = 2, .data = (unsigned char *)"aa"},
        {.len = 2, .data = (unsigned char *)"bb"},
    };
    xqc_moq_publish_namespace_done_msg_t done = {0};
    xqc_moq_publish_namespace_done_msg_t decoded = {0};
    xqc_moq_decode_msg_ctx_t msg_ctx = {0};
    uint8_t buf[128] = {0};
    xqc_int_t finish = 0;
    xqc_int_t wait_more_data = 0;
    xqc_int_t len;
    xqc_int_t ret;

    xqc_moq_msg_publish_namespace_done_init_handler(&done.msg_base);
    done.track_namespace_num = 2;
    done.track_namespace_tuple = ns;

    len = xqc_moq_msg_encode_publish_namespace_done_len(&done.msg_base);
    XQC_TEST_ASSERT(len > 0);

    ret = xqc_moq_msg_encode_publish_namespace_done(&done.msg_base, buf, sizeof(buf));
    XQC_TEST_ASSERT(ret == len);
    XQC_TEST_ASSERT(buf[0] == XQC_MOQ_MSG_PUBLISH_NAMESPACE_DONE);

    xqc_moq_msg_publish_namespace_done_init_handler(&decoded.msg_base);
    ret = xqc_moq_msg_decode_publish_namespace_done(buf + 1, ret - 1, 0, &msg_ctx, &decoded.msg_base,
                                                    &finish, &wait_more_data);

    XQC_TEST_ASSERT(ret == len - 1);
    XQC_TEST_ASSERT(finish == 1);
    XQC_TEST_ASSERT(wait_more_data == 0);
    XQC_TEST_ASSERT(decoded.track_namespace_num == 2);
    XQC_TEST_ASSERT(decoded.track_namespace_tuple[0].len == 2);
    XQC_TEST_ASSERT(memcmp(decoded.track_namespace_tuple[0].data, "aa", 2) == 0);
    XQC_TEST_ASSERT(decoded.track_namespace_tuple[1].len == 2);
    XQC_TEST_ASSERT(memcmp(decoded.track_namespace_tuple[1].data, "bb", 2) == 0);

    for (uint64_t i = 0; i < decoded.track_namespace_num; i++) {
        xqc_free(decoded.track_namespace_tuple[i].data);
    }
    xqc_free(decoded.track_namespace_tuple);
    return 0;
}

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
    if (xqc_test_setup_roundtrip() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_setup_empty_options() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_publish_namespace_vi64_encoding() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_request_ok_vi64_decoding() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_subscribe_request_vi64_encoding() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_subscribe_ok_response_vi64_roundtrip() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_request_error_fragmented_decoding() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_advertised_namespace_registry_lifecycle() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_publish_namespace_done_request_id_decoding() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_publish_namespace_rejects_oversized_tuple() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_namespace_root_done_and_parent_child_rules() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_namespace_upgrade_keeps_parent() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_namespace_sibling_done_keeps_parent() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_publish_namespace_roundtrip() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_publish_namespace_done_roundtrip() != 0) {
        return EXIT_FAILURE;
    }

    if (xqc_test_publish_done_empty_reason_finishes() != 0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
