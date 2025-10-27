set(XQC_MOQ_VERSION "05" CACHE STRING "Select MoQ version (e.g., 05, 11)")
set_property(CACHE XQC_MOQ_VERSION PROPERTY STRINGS "05" "11") 

message(STATUS "Configuring MoQ demos for version: ${XQC_MOQ_VERSION}")

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

# set(
#     MOQ_DEMO_AUDIO_SERVER_SOURCE
#     "xqc_moq_audiodemo_server.c"
#     "xqc_moq_demo_comm.c"
# )


set(
    MOQ_DEFAULT_SERVER_SOURCE
    "xqc_moq_default_demo_server.c"
    "xqc_moq_demo_comm.c"
)

set(
    MOQ_DEFAULT_CLIENT_SOURCE
    "xqc_moq_default_demo_client.c"
    "xqc_moq_demo_comm.c"
)

# set(
#     MOQ_DEMO_RELAY_SOURCE
#     "xqc_moq_demo_relay.c"
#     "xqc_moq_demo_comm.c"
# )

# --- Include Directories (Common) ---
include_directories(
    "${CMAKE_SOURCE_DIR}/"
    "${CMAKE_SOURCE_DIR}/include"
    "${CMAKE_SOURCE_DIR}/tests"
    # ${CMAKE_SOURCE_DIR} # This seems redundant if CMAKE_SOURCE_DIR/ is already included
    ${CUNIT_INCLUDE_DIRS}
    ${LIBEVENT_INCLUDE_DIR}
)

# --- Define APP_DEPEND_LIBS ---
if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(APP_DEPEND_LIBS
        xquic-static
        ${SSL_LIB_PATH}
        ${LIBEVENT_LIBRARY}
        -lm)
else()
    set(APP_DEPEND_LIBS
        xquic-static
        ${SSL_LIB_PATH}
        ${LIBEVENT_LIBRARY}
        m
        dl
        stdc++
        pthread)
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(MOQ_DEMO_CLIENT_SOURCE ${MOQ_DEMO_CLIENT_SOURCE} ${GETOPT_SOURCES})
    set(MOQ_DEMO_SERVER_SOURCE ${MOQ_DEMO_SERVER_SOURCE} ${GETOPT_SOURCES})
    # set(MOQ_DEMO_AUDIO_SERVER_SOURCE ${MOQ_DEMO_AUDIO_SERVER_SOURCE} ${GETOPT_SOURCES})
endif()

# --- Determine Target Names Based on Version ---
if (XQC_MOQ_VERSION STREQUAL "11")
    set(MOQ_DEMO_CLIENT_TARGET_NAME "moq_demo_client_v11")
    set(MOQ_DEMO_SERVER_TARGET_NAME "moq_demo_server_v11")
    # set(MOQ_DEMO_AUDIO_SERVER_TARGET_NAME "moq_demo_audio_server_v11")
    set(MOQ_DEFAULT_CLIENT_TARGET_NAME "moq_default_demo_client")
    set(MOQ_DEFAULT_SERVER_TARGET_NAME "moq_default_demo_server")
    # set(MOQ_DEMO_RELAY_TARGET_NAME "moq_demo_relay_v11")
elseif (XQC_MOQ_VERSION STREQUAL "05")
    set(MOQ_DEMO_CLIENT_TARGET_NAME "moq_demo_client")
    set(MOQ_DEMO_SERVER_TARGET_NAME "moq_demo_server")
    # set(MOQ_DEMO_AUDIO_SERVER_TARGET_NAME "moq_demo_audio_server")
    set(MOQ_DEFAULT_CLIENT_TARGET_NAME "moq_default_demo_client")
    set(MOQ_DEFAULT_SERVER_TARGET_NAME "moq_default_demo_server")
else()
    message(FATAL_ERROR "Unsupported XQC_MOQ_VERSION: '${XQC_MOQ_VERSION}'. Please use '05' or '11'.")
endif()

if (XQC_MOQ_VERSION STREQUAL "11")
    add_executable(${MOQ_DEMO_CLIENT_TARGET_NAME} ${MOQ_DEMO_CLIENT_SOURCE})
    add_executable(${MOQ_DEMO_SERVER_TARGET_NAME} ${MOQ_DEMO_SERVER_SOURCE})
    # add_executable(${MOQ_DEMO_AUDIO_SERVER_TARGET_NAME} ${MOQ_DEMO_AUDIO_SERVER_SOURCE})
    add_executable(${MOQ_DEFAULT_CLIENT_TARGET_NAME} ${MOQ_DEFAULT_CLIENT_SOURCE})
    add_executable(${MOQ_DEFAULT_SERVER_TARGET_NAME} ${MOQ_DEFAULT_SERVER_SOURCE})
    # add_executable(${MOQ_DEMO_RELAY_TARGET_NAME} ${MOQ_DEMO_RELAY_SOURCE})
endif()

if (XQC_MOQ_VERSION STREQUAL "05")
    add_executable(${MOQ_DEMO_CLIENT_TARGET_NAME} ${MOQ_DEMO_CLIENT_SOURCE})
    add_executable(${MOQ_DEMO_SERVER_TARGET_NAME} ${MOQ_DEMO_SERVER_SOURCE})
    # add_executable(${MOQ_DEMO_AUDIO_SERVER_TARGET_NAME} ${MOQ_DEMO_AUDIO_SERVER_SOURCE})
    add_executable(${MOQ_DEFAULT_CLIENT_TARGET_NAME} ${MOQ_DEFAULT_CLIENT_SOURCE})
    add_executable(${MOQ_DEFAULT_SERVER_TARGET_NAME} ${MOQ_DEFAULT_SERVER_SOURCE})
endif()

if (XQC_MOQ_VERSION STREQUAL "11")
    target_link_libraries(${MOQ_DEMO_CLIENT_TARGET_NAME} ${APP_DEPEND_LIBS})
    target_link_libraries(${MOQ_DEMO_SERVER_TARGET_NAME} ${APP_DEPEND_LIBS})
    # target_link_libraries(${MOQ_DEMO_AUDIO_SERVER_TARGET_NAME} ${APP_DEPEND_LIBS})
    target_link_libraries(${MOQ_DEFAULT_CLIENT_TARGET_NAME} ${APP_DEPEND_LIBS})
    target_link_libraries(${MOQ_DEFAULT_SERVER_TARGET_NAME} ${APP_DEPEND_LIBS})
    # target_link_libraries(${MOQ_DEMO_RELAY_TARGET_NAME} ${APP_DEPEND_LIBS})
endif()

if (XQC_MOQ_VERSION STREQUAL "05")
    target_link_libraries(${MOQ_DEMO_CLIENT_TARGET_NAME} ${APP_DEPEND_LIBS})
    target_link_libraries(${MOQ_DEMO_SERVER_TARGET_NAME} ${APP_DEPEND_LIBS})
    # target_link_libraries(${MOQ_DEMO_AUDIO_SERVER_TARGET_NAME} ${APP_DEPEND_LIBS})
    target_link_libraries(${MOQ_DEFAULT_CLIENT_TARGET_NAME} ${APP_DEPEND_LIBS})
    target_link_libraries(${MOQ_DEFAULT_SERVER_TARGET_NAME} ${APP_DEPEND_LIBS})
endif()

if (XQC_MOQ_VERSION STREQUAL "11")
    target_compile_definitions(${MOQ_DEMO_CLIENT_TARGET_NAME} PUBLIC XQC_MOQ_VERSION_11)
    target_compile_definitions(${MOQ_DEMO_SERVER_TARGET_NAME} PUBLIC XQC_MOQ_VERSION_11)
    # target_compile_definitions(${MOQ_DEMO_AUDIO_SERVER_TARGET_NAME} PUBLIC XQC_MOQ_VERSION_11)
    target_compile_definitions(${MOQ_DEFAULT_CLIENT_TARGET_NAME} PUBLIC XQC_MOQ_VERSION_11)
    target_compile_definitions(${MOQ_DEFAULT_SERVER_TARGET_NAME} PUBLIC XQC_MOQ_VERSION_11)
    # target_compile_definitions(${MOQ_DEMO_RELAY_TARGET_NAME} PUBLIC XQC_MOQ_VERSION_11)
elseif (XQC_MOQ_VERSION STREQUAL "05")
     target_compile_definitions(${MOQ_DEMO_CLIENT_TARGET_NAME} PUBLIC XQC_MOQ_VERSION_05)
     target_compile_definitions(${MOQ_DEMO_SERVER_TARGET_NAME} PUBLIC XQC_MOQ_VERSION_05)
    #  target_compile_definitions(${MOQ_DEMO_AUDIO_SERVER_TARGET_NAME} PUBLIC XQC_MOQ_VERSION_05)
    #  target_compile_definitions(${MOQ_CLOCK_CLIENT_TARGET_NAME} PUBLIC XQC_MOQ_VERSION_05)
    #  target_compile_definitions(${MOQ_CLOCK_SERVER_TARGET_NAME} PUBLIC XQC_MOQ_VERSION_05)
     target_compile_definitions(${MOQ_DEFAULT_CLIENT_TARGET_NAME} PUBLIC XQC_MOQ_VERSION_05)
     target_compile_definitions(${MOQ_DEFAULT_SERVER_TARGET_NAME} PUBLIC XQC_MOQ_VERSION_05)
endif()
# 添加测试客户端
set(MOQ_DEMO_RELAY_TEST_CLIENT_SOURCES
    xqc_moq_demo_relay_client.c
    xqc_moq_demo_comm.c
)

add_executable(moq_demo_relay_test_client
    xqc_moq_demo_relay_client.c
    xqc_moq_demo_comm.c
)

target_link_libraries(moq_demo_relay_test_client ${APP_DEPEND_LIBS})
target_compile_definitions(moq_demo_relay_test_client PRIVATE XQC_MOQ_VERSION_11)

set(MOQ_DEMO_RELAY_TEST_SERVER_SOURCES
    xqc_moq_demo_relay_test_server.c
    xqc_moq_demo_comm.c
)

add_executable(moq_demo_relay_test_server
    xqc_moq_demo_relay_test_server.c
    xqc_moq_demo_comm.c
)

target_link_libraries(moq_demo_relay_test_server ${APP_DEPEND_LIBS})
target_compile_definitions(moq_demo_relay_test_server PRIVATE XQC_MOQ_VERSION_11)

add_executable(moq_relay_test_client
    xqc_moq_demo_relay_client.c
    xqc_moq_demo_comm.c
)

target_link_libraries(moq_relay_test_client ${APP_DEPEND_LIBS})
target_compile_definitions(moq_relay_test_client PRIVATE XQC_MOQ_VERSION_11)

