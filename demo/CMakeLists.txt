### hq demo client/server ###
set(
    HQ_SOURCES
    "xqc_hq_ctx.c"
    "xqc_hq_conn.c"
    "xqc_hq_request.c"
)

set(
    DEMO_CLIENT_SOURCES
    ${HQ_SOURCES}
    "demo_client.c"
    "xqc_wt_app.c"
    "xqc_wt_echo_client.c"
    "xqc_wt_echo_policy.c"
    "${CMAKE_SOURCE_DIR}/case_test/webtransport/xqc_webtrans_test_cases.c"
)

set(
    DEMO_SERVER_SOURCES
    ${HQ_SOURCES}
    "demo_server.c"
    "xqc_wt_app.c"
    "xqc_wt_echo_server.c"
    "xqc_wt_echo_policy.c"
    "${CMAKE_SOURCE_DIR}/case_test/webtransport/xqc_webtrans_test_cases.c"
)


if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(DEMO_SERVER_SOURCES
        ${DEMO_SERVER_SOURCES}
        ${GETOPT_SOURCES}
    )

    set(DEMO_CLIENT_SOURCES
        ${DEMO_CLIENT_SOURCES}
        ${GETOPT_SOURCES}
    )
endif()

include_directories(
    "${CMAKE_SOURCE_DIR}/"
    "${CMAKE_SOURCE_DIR}/include"
    ${CMAKE_SOURCE_DIR}
    ${CUNIT_INCLUDE_DIRS}
    ${LIBEVENT_INCLUDE_DIR}
)

add_executable(demo_server ${DEMO_SERVER_SOURCES})
add_executable(demo_client ${DEMO_CLIENT_SOURCES})

target_link_libraries(demo_server ${APP_DEPEND_LIBS})
target_link_libraries(demo_client ${APP_DEPEND_LIBS})

if(XQC_ENABLE_WEBTRANSPORT_INTEROP AND NOT UNIX)
    message(FATAL_ERROR
        "XQC_ENABLE_WEBTRANSPORT_INTEROP requires a POSIX platform")
endif()

if(XQC_ENABLE_WEBTRANSPORT_INTEROP)
    target_sources(demo_client PRIVATE "xqc_webtrans_interop.c")
    target_sources(demo_server PRIVATE "xqc_webtrans_interop.c")
    target_compile_definitions(demo_client PRIVATE
        XQC_ENABLE_WEBTRANSPORT_INTEROP=1)
    target_compile_definitions(demo_server PRIVATE
        XQC_ENABLE_WEBTRANSPORT_INTEROP=1)
endif()
