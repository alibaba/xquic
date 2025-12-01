### hq demo client/server ###
set(
    HQ_SOURCES
    "../../demo/xqc_hq_ctx.c"
    "../../demo/xqc_hq_conn.c"
    "../../demo/xqc_hq_request.c"
)


set(
    WT_DEMO_BASE_SOURCES
    # ${HQ_SOURCES}
    "xqc_webtransport_ctx.c"
    "xqc_webtransport_conn.c"
    "xqc_webtransport_request.c"
    "xqc_webtransport_defs.c"
    "xqc_webtransport_dgram.c"
    "xqc_webtransport_session.c"
    "xqc_webtransport_stream.c"
    "xqc_webtransport_wire.c"
)
set (
    NEW_WT_DEMO_SERVER_SOURCES
    ${WT_DEMO_BASE_SOURCES}
    "wt_demo_server.c"
)
    
    
set(
    WT_VIDEO_SYNC_SERVER_SOURCES
    ${WT_DEMO_BASE_SOURCES}
    "wt_video_sync_server.cpp"
    "wt_video_sync.cpp"
)


if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(DEMO_SERVER_SOURCES
        ${DEMO_SERVER_SOURCES}
        ${GETOPT_SOURCES}
    )

    set(WT_DEMO_SERVER_SOURCES
        ${WT_DEMO_SERVER_SOURCES}
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



# add_executable(wt_test_server ${WT_DEMO_SERVER_SOURCES})
# add_executable(wt_video_sync_server ${WT_VIDEO_SYNC_SERVER_SOURCES})
add_executable(wt_test_server ${NEW_WT_DEMO_SERVER_SOURCES})

# target_link_libraries(wt_test_server ${APP_DEPEND_LIBS})
# target_link_libraries(wt_video_sync_server ${APP_DEPEND_LIBS})
target_link_libraries(wt_test_server ${APP_DEPEND_LIBS})
