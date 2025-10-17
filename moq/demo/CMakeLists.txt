set(
    MOQ_DEMO_CLIENT_SOURCE
    "xqc_moq_demo_client.c"
    "xqc_moq_demo_comm.c"
)

set(
    MOQ_DEMO_SERVER_SOURCE
    "xqc_moq_demo_server.c"
    "xqc_moq_demo_comm.c"
)

set(
    MOQ_DEMO_AUDIO_SERVER_SOURCE
    "xqc_moq_audiodemo_server.c"
    "xqc_moq_demo_comm.c"
)


include_directories(
    "${CMAKE_SOURCE_DIR}/"
    "${CMAKE_SOURCE_DIR}/include"
    "${CMAKE_SOURCE_DIR}/tests"
    ${CMAKE_SOURCE_DIR}
    ${CUNIT_INCLUDE_DIRS}
    ${LIBEVENT_INCLUDE_DIR}
)


if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(MOQ_DEMO_CLIENT_SOURCE
        ${MOQ_DEMO_CLIENT_SOURCE}
        ${GETOPT_SOURCES}
    )
    set(MOQ_DEMO_SERVER_SOURCE
        ${MOQ_DEMO_SERVER_SOURCE}
        ${GETOPT_SOURCES}
    )
    set(MOQ_DEMO_AUDIO_SERVER_SOURCE
        ${MOQ_DEMO_AUDIO_SERVER_SOURCE}
        ${GETOPT_SOURCES}
    )
endif()

add_executable(moq_demo_client ${MOQ_DEMO_CLIENT_SOURCE})
add_executable(moq_demo_server ${MOQ_DEMO_SERVER_SOURCE})
add_executable(moq_demo_audio_server ${MOQ_DEMO_AUDIO_SERVER_SOURCE})


target_link_libraries(moq_demo_client ${APP_DEPEND_LIBS})
target_link_libraries(moq_demo_server ${APP_DEPEND_LIBS})
target_link_libraries(moq_demo_audio_server ${APP_DEPEND_LIBS})
