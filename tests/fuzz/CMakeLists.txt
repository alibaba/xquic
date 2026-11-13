##### libFuzzer targets, built with -DXQC_ENABLE_FUZZ=ON (see README.md) #####

set(XQC_FUZZ_TARGETS
    fuzz_conn
    fuzz_frame_parse
    fuzz_h3_frame
    fuzz_packet_header
    fuzz_qpack
    fuzz_quic_lb
    fuzz_token
    fuzz_transport_params
)

if(XQC_ENABLE_WEBTRANSPORT)
    list(APPEND XQC_FUZZ_TARGETS fuzz_wt_capsule)
endif()

if(XQC_ENABLE_MOQ)
    list(APPEND XQC_FUZZ_TARGETS fuzz_moq_message)
endif()

if(NOT CMAKE_SYSTEM_NAME MATCHES "Windows")
    set(XQC_FUZZ_LIBS m dl stdc++ pthread)
endif()

foreach(target ${XQC_FUZZ_TARGETS})
    add_executable(${target} ${target}.c xqc_fuzz_common.c)
    target_include_directories(${target} PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${SSL_INC_PATH}
    )
    target_link_libraries(${target}
        xquic-static
        ${SSL_LIB_PATH}
        ${XQC_FUZZ_LIBS}
        ${XQC_FUZZ_ENGINE}
    )
endforeach()
