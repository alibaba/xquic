/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include <CUnit/CUnit.h>
#include "xqc_moqt_quic_test.h"
#include "xqc_common_test.h"
#include "include/moq/xqc_moq.h"
#include "include/moq/xqc_moqt.h"
#include "src/transport/xqc_conn.h"
#include "tests/complex_case/complex_case_common.h"

static xqc_int_t xqc_moqt_test_conn_notify(xqc_connection_t *conn,
    const xqc_cid_t *cid, void *user_data, void *protocol_data);

static xqc_int_t
xqc_moqt_test_conn_notify(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *user_data, void *protocol_data)
{
    return XQC_OK;
}

void
xqc_test_moqt_config(void)
{
    xqc_moqt_config_t  config;
    const unsigned    unsupported[] = {0, 5, 23, 24, UINT32_MAX};

    /* Draft-22 section 6.2: the ALPN identifies the selected wire version. */
    CU_ASSERT_EQUAL(xqc_moqt_config_init(&config, XQC_MOQT_VERSION_DRAFT_22),
                    XQC_OK);
    CU_ASSERT_EQUAL(config.version, XQC_MOQT_VERSION_DRAFT_22);
    CU_ASSERT_STRING_EQUAL(xqc_moqt_config_alpn(&config), "moqt-22");
    CU_ASSERT_PTR_NULL(xqc_moqt_config_alpn(NULL));
    CU_ASSERT_EQUAL(xqc_moqt_config_init(NULL, XQC_MOQT_VERSION_DRAFT_22),
                    -XQC_EPARAM);
    for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); i++) {
        CU_ASSERT_EQUAL(xqc_moqt_config_init(&config, unsupported[i]),
                        -XQC_EPARAM);
        CU_ASSERT_EQUAL(config.version, XQC_MOQT_VERSION_DRAFT_22);
        xqc_moqt_config_t invalid = {.version = unsupported[i]};
        CU_ASSERT_PTR_NULL(xqc_moqt_config_alpn(&invalid));
    }
}

void
xqc_test_moqt_alpn(void)
{
    xqc_engine_t              *engine = test_create_engine();
    xqc_moqt_config_t          config = {XQC_MOQT_VERSION_DRAFT_22};
    xqc_moqt_config_t          invalid = {0};
    xqc_conn_callbacks_t      cbs = {
        .conn_create_notify = xqc_moqt_test_conn_notify,
        .conn_close_notify = xqc_moqt_test_conn_notify,
    };
    xqc_app_proto_callbacks_t actual, legacy;
    const char               *old[] = {
        XQC_ALPN_MOQ_QUIC,
    };

    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
    xqc_moq_init_alpn(engine, &cbs, XQC_MOQ_TRANSPORT_QUIC);
    CU_ASSERT_EQUAL(xqc_moqt_init_alpn(engine, &config, &cbs), XQC_OK);
    CU_ASSERT_EQUAL(xqc_engine_get_alpn_callbacks(
        engine, "moqt-22",
        sizeof("moqt-22") - 1, &actual), XQC_OK);
    CU_ASSERT(actual.conn_cbs.conn_create_notify == cbs.conn_create_notify);
    CU_ASSERT(actual.conn_cbs.conn_close_notify == cbs.conn_close_notify);
    CU_ASSERT_PTR_NOT_NULL(actual.stream_cbs.stream_read_notify);
    CU_ASSERT_PTR_NOT_NULL(actual.dgram_cbs.datagram_read_notify);
    for (size_t i = 0; i < sizeof(old) / sizeof(old[0]); i++) {
        CU_ASSERT_EQUAL(xqc_engine_get_alpn_callbacks(
            engine, old[i],
            strlen(old[i]), &legacy), XQC_OK);
        CU_ASSERT_PTR_NOT_NULL(legacy.stream_cbs.stream_read_notify);
        CU_ASSERT(legacy.conn_cbs.conn_create_notify == cbs.conn_create_notify);
    }

    CU_ASSERT_EQUAL(xqc_moqt_init_alpn(NULL, &config, &cbs), -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_moqt_init_alpn(engine, NULL, &cbs), -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_moqt_init_alpn(engine, &invalid, &cbs), -XQC_EPARAM);
    CU_ASSERT_EQUAL(xqc_moqt_init_alpn(engine, &config, NULL), -XQC_EPARAM);
    /* The engine copies callbacks; a subsequent registration replaces them. */
    cbs.conn_close_notify = NULL;
    CU_ASSERT(actual.conn_cbs.conn_close_notify != NULL);
    CU_ASSERT_EQUAL(xqc_moqt_init_alpn(engine, &config, &cbs), XQC_OK);
    CU_ASSERT_EQUAL(xqc_engine_get_alpn_callbacks(
        engine, "moqt-22",
        sizeof("moqt-22") - 1, &actual), XQC_OK);
    CU_ASSERT_PTR_NULL(actual.conn_cbs.conn_close_notify);
    CU_ASSERT_EQUAL(xqc_engine_unregister_alpn(engine, "moqt-22",
                                               sizeof("moqt-22") - 1), XQC_OK);
    xqc_engine_destroy(engine);
}

void
xqc_test_moqt_connect(void)
{
    xqc_engine_t          *engine = test_create_engine();
    xqc_moqt_config_t      config = {XQC_MOQT_VERSION_DRAFT_22};
    xqc_conn_callbacks_t  cbs = {0};
    xqc_conn_settings_t   settings = {.proto_version = XQC_VERSION_V1,
        .max_datagram_frame_size = XQC_MAX_PACKET_OUT_SIZE};
    xqc_conn_ssl_config_t ssl = {0};
    const xqc_cid_t       *cid;
    xqc_connection_t      *conn;

    CU_ASSERT_PTR_NOT_NULL_FATAL(engine);
    CU_ASSERT_EQUAL(xqc_moqt_init_alpn(engine, &config, &cbs), XQC_OK);
    cid = xqc_moqt_connect(engine, &config, &settings, NULL, 0, "localhost",
                           &ssl, NULL, 0, &config);
    CU_ASSERT_PTR_NOT_NULL_FATAL(cid);
    conn = xqc_engine_conns_hash_find(engine, cid, 's');
    CU_ASSERT_PTR_NOT_NULL_FATAL(conn);
    CU_ASSERT_STRING_EQUAL(conn->alpn, "moqt-22");
    CU_ASSERT_FALSE(conn->local_settings.no_crypto);
    CU_ASSERT(conn->user_data == &config);
    config.version = 0;
    CU_ASSERT_STRING_EQUAL(conn->alpn, "moqt-22");
    CU_ASSERT_PTR_NULL(xqc_moqt_connect(engine, &config, &settings, NULL, 0,
                                        "localhost", &ssl, NULL, 0, NULL));
    config.version = XQC_MOQT_VERSION_DRAFT_22;

    CU_ASSERT_PTR_NULL(xqc_moqt_connect(NULL, &config, &settings, NULL, 0,
                                        "localhost", &ssl, NULL, 0, NULL));
    CU_ASSERT_PTR_NULL(xqc_moqt_connect(engine, NULL, &settings, NULL, 0,
                                        "localhost", &ssl, NULL, 0, NULL));
    CU_ASSERT_PTR_NULL(xqc_moqt_connect(engine, &config, NULL, NULL, 0,
                                        "localhost", &ssl, NULL, 0, NULL));
    CU_ASSERT_PTR_NULL(xqc_moqt_connect(engine, &config, &settings, NULL, 0,
                                        "localhost", NULL, NULL, 0, NULL));
    settings.max_datagram_frame_size = 0;
    CU_ASSERT_PTR_NULL(xqc_moqt_connect(engine, &config, &settings, NULL, 0,
                                        "localhost", &ssl, NULL, 0, NULL));
    settings.max_datagram_frame_size = XQC_MAX_PACKET_OUT_SIZE;

    /* Recovery requires the later explicit MoQT opt-in contract. */
    ssl.session_ticket_data = "ticket";
    CU_ASSERT_PTR_NULL(xqc_moqt_connect(engine, &config, &settings, NULL, 0,
                                        "localhost", &ssl, NULL, 0, NULL));
    CU_ASSERT_STRING_EQUAL(ssl.session_ticket_data, "ticket");
    ssl.session_ticket_data = NULL;
    ssl.session_ticket_len = 1;
    CU_ASSERT_PTR_NULL(xqc_moqt_connect(engine, &config, &settings, NULL, 0,
                                        "localhost", &ssl, NULL, 0, NULL));
    ssl.session_ticket_len = 0;
    ssl.transport_parameter_data = "params";
    CU_ASSERT_PTR_NULL(xqc_moqt_connect(engine, &config, &settings, NULL, 0,
                                        "localhost", &ssl, NULL, 0, NULL));
    ssl.transport_parameter_data = NULL;
    ssl.transport_parameter_data_len = 1;
    CU_ASSERT_PTR_NULL(xqc_moqt_connect(engine, &config, &settings, NULL, 0,
                                        "localhost", &ssl, NULL, 0, NULL));
    ssl.transport_parameter_data_len = 0;
    CU_ASSERT_EQUAL(xqc_engine_unregister_alpn(engine, "moqt-22",
                                               sizeof("moqt-22") - 1), XQC_OK);
    CU_ASSERT_PTR_NULL(xqc_moqt_connect(engine, &config, &settings, NULL, 0,
                                        "localhost", &ssl, NULL, 0, NULL));
    xqc_engine_destroy(engine);
}
