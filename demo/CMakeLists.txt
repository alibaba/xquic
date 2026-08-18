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
)

set(
    DEMO_SERVER_SOURCES
    ${HQ_SOURCES}
    "demo_server.c"
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
