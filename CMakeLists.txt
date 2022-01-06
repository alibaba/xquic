# Copyright (c) 2022, Alibaba Group Holding Limited

cmake_minimum_required (VERSION 2.6)
project (xquic)

set (xquic_VERSION_MAJOR 0)
set (xquic_VERSION_MINOR 1)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# SSL lib type, xquic support babassl and boringssl interfaces
if(NOT SSL_TYPE)
    set(SSL_TYPE "babassl")
endif()

# PATH of ssl
if(NOT SSL_PATH)
    set(SSL_PATH "/usr/local/babassl")
endif()

# ssl include path
if(NOT SSL_INC_PATH)
    set(SSL_INC_PATH
        ${SSL_PATH}/include
    )
endif()

# ssl lib denpendency
if(NOT SSL_LIB_PATH)
    set(SSL_LIB_PATH
        ${SSL_PATH}/lib/libssl.a
        ${SSL_PATH}/lib/libcrypto.a
    )
endif()

# print tls traffic secret in keylog
if(XQC_PRINT_SECRET)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DXQC_PRINT_SECRET")
endif()

# print only error log
if(XQC_ONLY_ERROR_LOG)
    set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -DXQC_ONLY_ERROR_LOG ")
endif()

# enable event log
if(XQC_ENABLE_EVENT_LOG)
    set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -DXQC_ENABLE_EVENT_LOG ")
endif()

# sendmmsg
if(XQC_SUPPORT_SENDMMSG_BUILD)
    add_definitions(-DXQC_SUPPORT_SENDMMSG)
endif()

#coverity
if(GCOV STREQUAL "on")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
endif()



# C_FLAGS
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O2 -std=gnu11 -Werror -Wall -Wno-unused -Wno-pointer-sign -Wno-format-security -DNDEBUG_PRINT -DNPRINT_MALLOC ")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} -g -O0 -std=gnu11 -Werror -Wall -Wno-unused -Wno-pointer-sign -Wno-format-security -DNDEBUG_PRINT -DNPRINT_MALLOC -DXQC_DEBUG ")

# additional C_FLAGS on mac
if(PLATFORM STREQUAL "mac32")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
endif()


# configure file
configure_file (
    xqc_configure.h.in
    xqc_configure.h
)

include_directories(
    include
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_BINARY_DIR}/include"
)



# http3/qpack source
set(
    HTTP3_SOURCES
    "src/http3/xqc_var_buf.c"
    "src/http3/xqc_h3_conn.c"
    "src/http3/xqc_h3_stream.c"
    "src/http3/xqc_h3_request.c"
    "src/http3/frame/xqc_h3_frame.c"
    "src/http3/xqc_h3_header.c"
    "src/http3/xqc_h3_ctx.c"
    "src/http3/xqc_h3_defs.c"
    "src/http3/qpack/xqc_qpack.c"
    "src/http3/qpack/xqc_prefixed_int.c"
    "src/http3/qpack/xqc_prefixed_str.c"
    "src/http3/qpack/xqc_decoder.c"
    "src/http3/qpack/xqc_encoder.c"
    "src/http3/qpack/xqc_rep.c"
    "src/http3/qpack/xqc_ins.c"
    "src/http3/qpack/stable/xqc_stable.c"
    "src/http3/qpack/dtable/xqc_dtable.c"
)

# Transport source
set(
    TRANSPORT_SOURCES
    "src/transport/xqc_engine.c"
    "src/transport/xqc_conn.c"
    "src/transport/xqc_client.c"
    "src/transport/xqc_cid.c"
    "src/transport/xqc_packet_parser.c"
    "src/transport/xqc_frame_parser.c"
    "src/transport/xqc_stream.c"
    "src/transport/xqc_packet_out.c"
    "src/transport/xqc_packet_in.c"
    "src/transport/xqc_send_ctl.c"
    "src/transport/xqc_packet.c"
    "src/transport/xqc_frame.c"
    "src/transport/xqc_recv_record.c"
    "src/transport/xqc_pacing.c"
    "src/transport/xqc_utils.c"
    "src/transport/xqc_defs.c"
    "src/transport/xqc_transport_params.c"
)

# TLS source
set (
    TLS_SOURCE
    "src/tls/xqc_hkdf.c"
    "src/tls/xqc_null_crypto.c"
    "src/tls/xqc_crypto.c"
    "src/tls/xqc_tls_ctx.c"
    "src/tls/xqc_tls.c"
)

if(${SSL_TYPE} MATCHES "boringssl")
    set(
        TLS_SOURCE
        ${TLS_SOURCE}
        "src/tls/boringssl/xqc_hkdf.c"
        "src/tls/boringssl/xqc_crypto.c"
        "src/tls/boringssl/xqc_ssl_if.c"
    )
elseif(${SSL_TYPE} MATCHES "babassl")
    set(
        TLS_SOURCE
        ${TLS_SOURCE}
        "src/tls/babassl/xqc_hkdf.c"
        "src/tls/babassl/xqc_crypto.c"
        "src/tls/babassl/xqc_ssl_if.c"
    )
endif()

# common source
set(
    COMMON_SOURCES
    "src/common/xqc_random.c"
    "src/common/xqc_str.c"
    "src/common/xqc_log.c"
    "src/common/xqc_log_event_callback.c"
    "src/common/xqc_time.c"
    "src/common/utils/huffman/xqc_huffman_code.c"
    "src/common/utils/huffman/xqc_huffman.c"
    "src/common/utils/vint/xqc_discrete_vint_parser.c"
    "src/common/utils/vint/xqc_variable_len_int.c"
    "src/common/utils/ringarray/xqc_ring_array.c"
    "src/common/utils/ringmem/xqc_ring_mem.c"
    "src/common/utils/2d_hash/xqc_2d_hash_table.c"
)

# congestion control
set(
    CONGESTION_CONTROL_SOURCES
    "src/congestion_control/xqc_cubic.c"
    "src/congestion_control/xqc_bbr.c"
    "src/congestion_control/xqc_window_filter.c"
    "src/congestion_control/xqc_sample.c"
)

if(XQC_DISABLE_RENO)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DXQC_DISABLE_RENO ")
else()
    set(
        CONGESTION_CONTROL_SOURCES
        ${CONGESTION_CONTROL_SOURCES}
        "src/congestion_control/xqc_new_reno.c"
    )
endif()

if(XQC_ENABLE_BBR2)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DXQC_ENABLE_BBR2 ")
    set(
        CONGESTION_CONTROL_SOURCES

        ${CONGESTION_CONTROL_SOURCES}
        "src/congestion_control/xqc_bbr2.c"
    )
endif()

# xquic source
set (
    XQC_SOURCE 
    ${HTTP3_SOURCES}
    ${TRANSPORT_SOURCES}
    ${TLS_SOURCE}
    ${COMMON_SOURCES}
    ${CONGESTION_CONTROL_SOURCES}
)



# target
add_library(
    xquic-static
    STATIC
    ${XQC_SOURCE}
)

add_library(
    xquic
    SHARED
    ${XQC_SOURCE}
)

if(PLATFORM MATCHES "mac")
    target_link_libraries(
        xquic
        "-ldl -Wl,-all_load"
        ${SSL_LIB_PATH}
        "-Wl"
        -lpthread
    )
else()
    target_link_libraries(
        xquic
        "-ldl -Wl,--whole-archive -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/scripts/xquic.lds"
        ${SSL_LIB_PATH}
        "-Wl,--no-whole-archive"
        -lpthread
    )
endif()



# Strip binary for release builds
if(CMAKE_BUILD_TYPE STREQUAL MinSizeRel)
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_STRIP} libxquic.so)
endif()


include_directories(${SSL_INC_PATH})
include_directories(${CMAKE_SOURCE_DIR}/)



##### build unittest, test client/server, demo client/server #####
if (XQC_ENABLE_TESTING)
    # CUnit
    find_package(CUnit 2.1)
    enable_testing()
    set(HAVE_CUNIT ${CUNIT_FOUND})
    if(HAVE_CUNIT)
        add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})
    endif()

    add_subdirectory(tests)

    ### test client/server ###
    add_executable(test_server tests/test_server.c)
    add_executable(test_client tests/test_client.c)

    ### hq demo client/server ###
    set(
        HQ_SOURCES
        "demo/xqc_hq_ctx.c"
        "demo/xqc_hq_conn.c"
        "demo/xqc_hq_request.c"
    )

    set(
        DEMO_CLIENT_SOURCES
        ${HQ_SOURCES}
        "demo/demo_client.c"
    )

    set(
        DEMO_SERVER_SOURCES
        ${HQ_SOURCES}
        "demo/demo_server.c"
    )

    add_executable(demo_server ${DEMO_SERVER_SOURCES})
    add_executable(demo_client ${DEMO_CLIENT_SOURCES})

    link_directories( /usr/local/lib )

    if(PLATFORM STREQUAL "mac32")
        target_link_libraries(test_server xquic  -lm ${CMAKE_CURRENT_SOURCE_DIR}/../libevent32/lib/libevent.dylib)
        target_link_libraries(test_client xquic  -lm ${CMAKE_CURRENT_SOURCE_DIR}/../libevent32/lib/libevent.dylib)
        target_link_libraries(demo_server xquic  -lm ${CMAKE_CURRENT_SOURCE_DIR}/../libevent32/lib/libevent.dylib)
        target_link_libraries(demo_client xquic  -lm ${CMAKE_CURRENT_SOURCE_DIR}/../libevent32/lib/libevent.dylib)
    elseif(PLATFORM STREQUAL "mac")
        target_link_libraries(test_server xquic -lm -L/usr/local/lib -levent)
        target_link_libraries(test_client xquic -lm -L/usr/local/lib -levent)
        target_link_libraries(demo_server xquic -lm -L/usr/local/lib -levent)
        target_link_libraries(demo_client xquic -lm -L/usr/local/lib -levent)
    else()
        target_link_libraries(test_server xquic -levent -lm)
        target_link_libraries(test_client xquic -levent -lm)
        target_link_libraries(demo_server xquic -levent -lm)
        target_link_libraries(demo_client xquic -levent -lm)
    endif()

endif()

