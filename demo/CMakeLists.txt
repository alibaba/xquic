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
    "xqc_wt_echo_client.c"
    "${CMAKE_SOURCE_DIR}/case_test/webtransport/xqc_webtrans_test_cases.c"
)

set(
    DEMO_SERVER_SOURCES
    ${HQ_SOURCES}
    "demo_server.c"
    "xqc_wt_echo_server.c"
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

if(UNIX)
    foreach(role client server)
        add_executable(wt_interop_${role}
            ${HQ_SOURCES}
            "demo_${role}.c"
            "xqc_webtrans_interop.c"
        )
        target_compile_definitions(wt_interop_${role} PRIVATE
            XQC_WEBTRANSPORT_INTEROP=1
        )
        target_link_libraries(wt_interop_${role} ${APP_DEPEND_LIBS})
    endforeach()
endif()
