set(
    CATALOG_TEST_SOURCE
    "catalog_test.c"
    "../moq_media/xqc_moq_catalog.c"
    "../cjson/cJSON.c"
    "../moq_transport/xqc_moq_track.c"
)

set(
    JITTERBUFFER_TEST_SOURCE
    "video_jitter_buffer_test.c"
)

include_directories(
    "${CMAKE_SOURCE_DIR}/"
    "${CMAKE_SOURCE_DIR}/include"
    ${CMAKE_SOURCE_DIR}
    ${CUNIT_INCLUDE_DIRS}
    ${LIBEVENT_INCLUDE_DIR}
)


add_executable(catalog_test ${CATALOG_TEST_SOURCE})
target_link_libraries(catalog_test ${APP_DEPEND_LIBS})


add_executable(jitter_buffer_test ${JITTERBUFFER_TEST_SOURCE})
target_link_libraries(jitter_buffer_test ${APP_DEPEND_LIBS})