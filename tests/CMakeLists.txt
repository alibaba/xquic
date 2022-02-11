if(HAVE_CUNIT)
    include_directories(
        ${CMAKE_SOURCE_DIR}
        ${CUNIT_INCLUDE_DIRS}
    )

    set (UNIT_TEST_DIR unittest)

    set(test_SOURCES
        ${UNIT_TEST_DIR}/main.c
        ${UNIT_TEST_DIR}/xqc_random_test.c
        ${UNIT_TEST_DIR}/xqc_timer_test.c
        ${UNIT_TEST_DIR}/xqc_pq_test.c
        ${UNIT_TEST_DIR}/xqc_common_test.c
        ${UNIT_TEST_DIR}/xqc_conn_test.c
        ${UNIT_TEST_DIR}/xqc_engine_test.c
        ${UNIT_TEST_DIR}/xqc_common_test.c
        ${UNIT_TEST_DIR}/xqc_vint_test.c
        ${UNIT_TEST_DIR}/xqc_packet_test.c
        ${UNIT_TEST_DIR}/xqc_recv_record_test.c
        ${UNIT_TEST_DIR}/xqc_reno_test.c
        ${UNIT_TEST_DIR}/xqc_cubic_test.c
        ${UNIT_TEST_DIR}/xqc_stream_frame_test.c
        ${UNIT_TEST_DIR}/xqc_wakeup_pq_test.c
        ${UNIT_TEST_DIR}/xqc_process_frame_test.c
        ${UNIT_TEST_DIR}/xqc_tp_test.c
        ${UNIT_TEST_DIR}/xqc_tls_test.c
        ${UNIT_TEST_DIR}/xqc_crypto_test.c
        ${UNIT_TEST_DIR}/xqc_h3_test.c
        ${UNIT_TEST_DIR}/xqc_stable_test.c
        ${UNIT_TEST_DIR}/xqc_dtable_test.c
        ${UNIT_TEST_DIR}/utils/xqc_2d_hash_table_test.c
        ${UNIT_TEST_DIR}/utils/xqc_ring_array_test.c
        ${UNIT_TEST_DIR}/utils/xqc_ring_mem_test.c
        ${UNIT_TEST_DIR}/utils/xqc_huffman_test.c
        ${UNIT_TEST_DIR}/xqc_encoder_test.c
        ${UNIT_TEST_DIR}/xqc_qpack_test.c
        ${UNIT_TEST_DIR}/xqc_prefixed_str_test.c
        ${UNIT_TEST_DIR}/xqc_cid_test.c
        ${UNIT_TEST_DIR}/xqc_id_hash_test.c
    )


    add_executable(run_tests
        ${test_SOURCES}
    )

    target_include_directories(run_tests PRIVATE ${CUNIT_INCLUDE_DIRS})
    target_link_libraries(run_tests
        xquic-static
        ${CUNIT_LIBRARIES}
        ${SSL_LIB_PATH}
        m
        dl
        pthread
    )

    add_test(run_tests run_tests)
    add_dependencies(check run_tests)
    include_directories(${SSL_INC_PATH})

endif()
