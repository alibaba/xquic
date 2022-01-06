# find cunit

# find include dir
find_path(CUNIT_INCLUDE_DIR
  NAMES CUnit/CUnit.h
)

# find lib dir
find_library(CUNIT_LIBRARY
  NAMES cunit
)

# find version
if(CUNIT_INCLUDE_DIR)
  set(_version_regex "^#define[ \t]+CU_VERSION[ \t]+\"([^\"]+)\".*")
  file(STRINGS "${CUNIT_INCLUDE_DIR}/CUnit/CUnit.h"
    CUNIT_VERSION REGEX "${_version_regex}")
  string(REGEX REPLACE "${_version_regex}" "\\1"
    CUNIT_VERSION "${CUNIT_VERSION}")
  unset(_version_regex)
endif()

# check version requirement
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CUnit
                                  REQUIRED_VARS CUNIT_LIBRARY CUNIT_INCLUDE_DIR
                                  VERSION_VAR CUNIT_VERSION)

if(CUNIT_FOUND)
  set(CUNIT_LIBRARIES     ${CUNIT_LIBRARY})
  set(CUNIT_INCLUDE_DIRS  ${CUNIT_INCLUDE_DIR})
endif()

mark_as_advanced(
  CUNIT_INCLUDE_DIR
  CUNIT_LIBRARY
  )
