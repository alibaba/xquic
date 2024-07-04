##### build test_client/test_server, demo_client/demo_server #####
# CUnit TODO: fix test unit on windows
find_package(CUnit 2.1)
enable_testing()
set(HAVE_CUNIT ${CUNIT_FOUND})
if(HAVE_CUNIT)
    add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})
endif()

# find LibEvent include and library path
find_package(LibEvent 2.0.21)
if(NOT LIBEVENT_FOUND)
    message(FATAL_ERROR "libevent with required version not found")
endif()

include_directories(
    "${CMAKE_SOURCE_DIR}/"
    "${CMAKE_SOURCE_DIR}/include"
    ${CMAKE_SOURCE_DIR}
    ${CUNIT_INCLUDE_DIRS}
    ${LIBEVENT_INCLUDE_DIR}
)

set(TEST_SERVER_SOURCES
    test_server.c
)

set(TEST_CLIENT_SOURCES
    test_client.c
)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(GETOPT_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/getopt.c
        CACHE STRING "xquic windows getopt source")

    set(TEST_SERVER_SOURCES
        ${TEST_SERVER_SOURCES}
        ${GETOPT_SOURCES}
    )

    set(TEST_CLIENT_SOURCES
        ${TEST_CLIENT_SOURCES}
        ${GETOPT_SOURCES}
    )
endif()


### test client/server ###
add_executable(test_server ${TEST_SERVER_SOURCES})
add_executable(test_client ${TEST_CLIENT_SOURCES})


# link libraries
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    set(APP_DEPEND_LIBS
        xquic-static
        ${SSL_LIB_PATH}
        ${LIBEVENT_LIBRARY}
        -lm
        CACHE STRING "xquic app depend libs")
elseif(CMAKE_SYSTEM_NAME MATCHES "Darwin")
    set(APP_DEPEND_LIBS
        xquic-static
        ${SSL_LIB_PATH}
        ${LIBEVENT_LIBRARY}
        m
        dl
        pthread
        CACHE STRING "xquic app depend libs")
else()
    set(APP_DEPEND_LIBS
        xquic-static
        ${SSL_LIB_PATH}
        ${LIBEVENT_LIBRARY}
        stdc++
        m
        dl
        pthread
        CACHE STRING "xquic app depend libs")
endif()

target_link_libraries(test_server ${APP_DEPEND_LIBS})
target_link_libraries(test_client ${APP_DEPEND_LIBS})


# build run_tests
if(HAVE_CUNIT)

    set (UNIT_TEST_DIR unittest)

    set(test_SOURCES
        ${UNIT_TEST_DIR}/main.c
        ${UNIT_TEST_DIR}/xqc_random_test.c
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
        ${UNIT_TEST_DIR}/xqc_retry_test.c
        ${UNIT_TEST_DIR}/xqc_datagram_test.c
        ${UNIT_TEST_DIR}/xqc_h3_ext_test.c
    )

    if(XQC_ENABLE_FEC)
        set(
            test_SOURCES
            ${test_SOURCES}
            ${UNIT_TEST_DIR}/xqc_galois_test.c
            ${UNIT_TEST_DIR}/xqc_fec_scheme_test.c
            ${UNIT_TEST_DIR}/xqc_fec_test.c
        )
    endif()

    add_executable(run_tests
        ${test_SOURCES}
    )

    target_include_directories(run_tests
        PRIVATE
        ${INCLUDE_DIRECTORIES}
        ${CUNIT_INCLUDE_DIRS})

    if(CMAKE_SYSTEM_NAME MATCHES "Windows")
        set(CUTEST_DEPEND_LIBS
            xquic-static
            ${CUNIT_LIBRARIES}
            ${SSL_LIB_PATH}
            m
            CACHE STRING "xquic unit test depend libs")
    else()
        set(CUTEST_DEPEND_LIBS
            xquic-static
            ${CUNIT_LIBRARIES}
            ${SSL_LIB_PATH}
            stdc++
            m
            dl
            pthread
            CACHE STRING "xquic unit test depend libs")
    endif()
    
    target_link_libraries(run_tests
        ${CUTEST_DEPEND_LIBS}
    )

    add_test(run_tests run_tests)
    add_dependencies(check run_tests)
endif()

