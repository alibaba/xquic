# Copyright (c) 2022, Alibaba Group Holding Limited
# find the LibEvent library

# find include dir
find_path     (LIBEVENT_INCLUDE_DIR NAMES event.h
    PATHS ${LIBEVENT_DIR}
    PATH_SUFFIXES include)

# find dynamic library
find_library  (LIBEVENT_LIBRARY     NAMES event
    PATHS ${LIBEVENT_DIR}
    PATH_SUFFIXES lib lib64)
find_library  (LIBEVENT_SSL         NAMES event_openssl
    PATHS ${LIBEVENT_DIR}
    PATH_SUFFIXES lib lib64)
find_library  (LIBEVENT_CORE        NAMES event_core
    PATHS ${LIBEVENT_DIR}
    PATH_SUFFIXES lib lib64)
find_library  (LIBEVENT_EXTRA       NAMES event_extra
    PATHS ${LIBEVENT_DIR}
    PATH_SUFFIXES lib lib64)
find_library  (LIBEVENT_THREAD      NAMES event_pthreads
    PATHS ${LIBEVENT_DIR}
    PATH_SUFFIXES lib lib64)

# find version
if(LIBEVENT_INCLUDE_DIR)
    set(_version_regex
        "^#define[ ]+[EVENT__VERSION|_EVENT_VERSION]+[ ]+\"([^\"]+)\"")
    file(STRINGS "${LIBEVENT_INCLUDE_DIR}/event2/event-config.h"
        LIBEVENT_VERSION REGEX "${_version_regex}")

    # if event-config.h not found, try find event-config-64.h
    if(NOT LIBEVENT_VERSION)
        file(STRINGS "${LIBEVENT_INCLUDE_DIR}/event2/event-config-64.h"
            LIBEVENT_VERSION REGEX "${_version_regex}")
    endif()

    string(REGEX REPLACE "${_version_regex}" "\\1"
        LIBEVENT_VERSION "${LIBEVENT_VERSION}")
    unset(_version_regex)
endif()


include (FindPackageHandleStandardArgs)
set (LIBEVENT_INCLUDE_DIRS ${LIBEVENT_INCLUDE_DIR})

if(NOT ${LIBEVENT_LIBRARY} MATCHES "LIBEVENT_LIBRARY-NOTFOUND")
    set (LIBEVENT_LIBRARIES
        ${LIBEVENT_LIBRARIES}
        ${LIBEVENT_LIBRARY}
    )
endif()

if(NOT ${LIBEVENT_SSL} MATCHES "LIBEVENT_SSL-NOTFOUND")
    set (LIBEVENT_LIBRARIES
        ${LIBEVENT_LIBRARIES}
        ${LIBEVENT_SSL}
    )
endif()

if(NOT ${LIBEVENT_CORE} MATCHES "LIBEVENT_CORE-NOTFOUND")
    set (LIBEVENT_LIBRARIES
        ${LIBEVENT_LIBRARIES}
        ${LIBEVENT_CORE}
    )
endif()

if(NOT ${LIBEVENT_EXTRA} MATCHES "LIBEVENT_EXTRA-NOTFOUND")
    set (LIBEVENT_LIBRARIES
        ${LIBEVENT_LIBRARIES}
        ${LIBEVENT_EXTRA}
    )
endif()

if(NOT ${LIBEVENT_THREAD} MATCHES "LIBEVENT_THREAD-NOTFOUND")
    set (LIBEVENT_LIBRARIES
        ${LIBEVENT_LIBRARIES}
        ${LIBEVENT_THREAD}
    )
endif()


find_package_handle_standard_args(LibEvent
    REQUIRED_VARS
    LIBEVENT_INCLUDE_DIR
    LIBEVENT_LIBRARY
    LIBEVENT_LIBRARIES
    VERSION_VAR LIBEVENT_VERSION
)

mark_as_advanced(
    LIBEVENT_INCLUDE_DIRS
    LIBEVENT_LIBRARY
    LIBEVENT_LIBRARIES
)
