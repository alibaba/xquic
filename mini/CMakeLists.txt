### hq mini client/server ###
set(
    HQ_SOURCES
    "../demo/xqc_hq_ctx.c"
    "../demo/xqc_hq_conn.c"
    "../demo/xqc_hq_request.c"
)

set(
    MINI_CLIENT_SOURCES
    ${HQ_SOURCES}
    "common.c"
    "mini_client.c"
    "mini_client_cb.c"
)

set(
    MINI_SERVER_SOURCES
    ${HQ_SOURCES}
    "common.c"
    "mini_server.c"
    "mini_server_cb.c"
)


if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(MINI_SERVER_SOURCES
        ${MINI_SERVER_SOURCES}
        ${GETOPT_SOURCES}
    )

    set(MINI_CLIENT_SOURCES
        ${MINI_CLIENT_SOURCES}
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

add_executable(mini_server ${MINI_SERVER_SOURCES})
add_executable(mini_client ${MINI_CLIENT_SOURCES})

target_link_libraries(mini_server ${APP_DEPEND_LIBS})
target_link_libraries(mini_client ${APP_DEPEND_LIBS})
