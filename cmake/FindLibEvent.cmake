# find the LibEvent library

# find include dir
find_path     (LIBEVENT_INCLUDE_DIR     NAMES event.h)

# find dynamic library
find_library  (LIBEVENT_LIBRARY         NAMES event)

# find version
if(LIBEVENT_INCLUDE_DIR)
    set(_version_regex "^#define[ ]+[EVENT__VERSION|_EVENT_VERSION]+[ ]+\"([^\"]+)\"")
    file(STRINGS "${LIBEVENT_INCLUDE_DIR}/event2/event-config.h"
        LIBEVENT_VERSION REGEX "${_version_regex}")
    string(REGEX REPLACE "${_version_regex}" "\\1"
        LIBEVENT_VERSION "${LIBEVENT_VERSION}")
    unset(_version_regex)
endif()


include (FindPackageHandleStandardArgs)
set (LIBEVENT_INCLUDE_DIRS ${LIBEVENT_INCLUDE_DIR})
set (LIBEVENT_LIBRARIES
    ${LIBEVENT_LIBRARY}
    ${LIBEVENT_SSL}
    ${LIBEVENT_CORE}
    ${LIBEVENT_EXTRA}
    ${LIBEVENT_THREAD}
    ${LIBEVENT_EXTRA})

find_package_handle_standard_args(LibEvent
    REQUIRED_VARS
    LIBEVENT_INCLUDE_DIR
    LIBEVENT_LIBRARY
    LIBEVENT_LIBRARIES
    VERSION_VAR LIBEVENT_VERSION
)

mark_as_advanced(
    LIBEVENT_INCLUDE_DIRS
    LIBEVENT_LIBRARIES
)
