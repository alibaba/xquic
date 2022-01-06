# Copyright (c) 2022, Alibaba Group Holding Limited

cmake_minimum_required (VERSION 2.6)
project (xquic)

set (xquic_VERSION_MAJOR 0)
set (xquic_VERSION_MINOR 1)

set(CMAKE_C_STANDARD 11 )
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(XQC_BINARY_TYPE SHARED)

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

set(COMMON_FLAGS            "-Wall -Wno-deprecated  -Wno-unused -Wno-unused-variable -Wno-pointer-sign -Wno-format-security ")

set(COMMON_RELEASE_FLAGS    "-DNDEBUG")
set(COMMON_MIN_FLAGS        " ${COMMON_RELEASE_FLAGS} -Os -ffunction-sections -fdata-sections -fvisibility=hidden")
set(COMMON_DEBUG_FLAGS      " -O0")
if(GCOV)
    set(COMMON_DEBUG_FLAGS "${COMMON_DEBUG_FksLAGS} -fprofile-arcs -ftest-coverage")
endif()

if (CMAKE_BUILD_TYPE STREQUAL Release)
    set(DYNAMIC_COMPILE_FLAGS ${COMMON_RELEASE_FLAGS})
elseif(CMAKE_BUILD_TYPE STREQUAL Debug)
    set(DYNAMIC_COMPILE_FLAGS ${COMMON_DEBUG_FLAGS})
elseif(CMAKE_BUILD_TYPE STREQUAL Minsizerel)
    set(DYNAMIC_COMPILE_FLAGS ${COMMON_MIN_FLAGS})
    set(DYMAMIC_LINK_OPTION "-Wl,--gc-sections")
endif()


add_custom_target(xquic_global)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMMON_FLAGS} ${DYNAMIC_COMPILE_FLAGS}")

if (XQC_DISABLE_LOG)
    set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -DXQC_DISABLE_LOG")
endif()

if (XQC_ONLY_ERROR_LOG)
    set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -DXQC_ONLY_ERROR_LOG")
endif()

if (XQC_ENABLE_EVENT_LOG)
    set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -DXQC_ENABLE_EVENT_LOG ")
endif()

if(ANDROID)
    set(DYMAMIC_LINK_OPTION 
        ${DYMAMIC_LINK_OPTION}
        -lm
        -llog)

    if(NOT ANDROID_TOOLCHAIN_ROOT)
        message(FATAL_ERROR  "You Must Define DANDROID_TOOLCHAIN_ROOT")
    endif()

endif()


include(CMakeOptions.txt)

if (XQC_BUILD_OPENSSL)
    if(${SSL_TYPE} MATCHES "boringssl")
        add_subdirectory(${SSL_PATH})
        include_directories(${SSL_PATH}/include)

        if (BORINGSSL_PREFIX)
            add_definitions(-DBORINGSSL_PREFIX=${BORINGSSL_PREFIX})
            add_dependencies(xquic_global boringssl_prefix_symbols)
            include_directories(${SSL_PATH}/symbol_prefix_include)
        endif()

    else()
        #set(EXTRA_CONFIGURE_OPENSSL_PARAMS "${EXTRA_CONFIGURE_OPENSSL_PARAMS} ${DYNAMIC_COMPILE_FLAGS} ")
        #add_subdirectory(external/openssl-cmake)
    endif()

    set(DYMAMIC_LINK_OPTION 
            ssl 
            crypto 
            ${DYMAMIC_LINK_OPTION}
        )

elseif(XQC_EXISTS_OPENSSL)
    if(not XQC_EXISTS_OPENSSL_INCLUDE_DIR or not XQC_EXISTS_OPENSSL_BINARY)
        message(FATAL_ERROR  "You Must DEFINE XQC_EXISTS_OPENSSL_INCLUDE_DIR and XQC_EXISTS_OPENSSL_BINARY")
    endif()

    include_directories(XQC_EXISTS_OPENSSL_INCLUDE_DIR)
    set(DYMAMIC_LINK_OPTION "${XQC_EXISTS_OPENSSL_BINARY} ${DYMAMIC_LINK_OPTION}")

else()
    message(FATAL_ERROR  "There Must Exists one tls impl")
endif()


configure_file (xqc_configure.h.in include/xquic/xqc_configure.h  @ONLY)

include_directories(
    include/
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}/include
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

if (XQC_DISABLE_RENO)
    set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -DXQC_DISABLE_RENO")
else()
    set(
        CONGESTION_CONTROL_SOURCES
        ${CONGESTION_CONTROL_SOURCES}
        "src/congestion_control/xqc_new_reno.c"
    )
endif()

if (XQC_ENABLE_BBR2)
    set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -DXQC_ENABLE_BBR2")
    set(
        CONGESTION_CONTROL_SOURCES
        ${CONGESTION_CONTROL_SOURCES}
        "src/congestion_control/xqc_bbr2.c"
    )
endif()

if (XQC_NO_SHARED)
    set(XQC_BINARY_TYPE STATIC)
endif()

add_library(
    xquic
    ${XQC_BINARY_TYPE}
    ${HTTP3_SOURCES}
    ${TRANSPORT_SOURCES}
    ${TLS_SOURCE}
    ${COMMON_SOURCES}
    ${CONGESTION_CONTROL_SOURCES}
)

add_dependencies(xquic xquic_global)

if (NOT XQC_NO_SHARED)
    target_link_libraries(
        xquic 
        ${DYMAMIC_LINK_OPTION}
        -pthread
    )
endif()

if (XQC_ENABLE_TESTING)
    set(CMAKE_MODULE_PATH       "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
    find_package(CUnit REQUIRED)
    include_directories(${CUNIT_INCLUDE_DIR})
    enable_testing()
    add_subdirectory(tests)
    add_subdirectory(tests/unittest)
endif()

if (XQC_BUILD_SAMPLE)
    add_subdirectory(third_party/libevent)
    include_directories(third_party/libevent/include  ${CMAKE_CURRENT_BINARY_DIR}/third_party/libevent/include )
    add_executable(test_client tests/test_client.c)
    add_executable(test_server tests/test_server.c)
    target_link_libraries(test_client xquic event)
    target_link_libraries(test_server xquic event)
endif()
