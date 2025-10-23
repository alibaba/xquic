# Copyright (c) 2022, Alibaba Group Holding Limited
# find the SSL library, success when SSL_INCLUDE_DIR and SSL_LIBRARIES_STATIC is
# not empty, no matter if SSL_LIBRARIES is empty or not.

# find include dir
find_path(SSL_INCLUDE_DIR           NAMES openssl/ssl.h
    PATHS ${SSL_DIR}
    PATH_SUFFIXES include
    NO_DEFAULT_PATH)

# find ssl library
find_library(SSL_LIBRARY            NAMES ssl
    PATHS ${SSL_DIR}
    PATH_SUFFIXES lib64 lib build build/ssl
    NO_DEFAULT_PATH)

# find crypto library
find_library(CRYPTO_LIBRARY         NAMES crypto
    PATHS ${SSL_DIR}
    PATH_SUFFIXES lib64 lib build build/crypto
    NO_DEFAULT_PATH)


if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    set(SSL_LIBRARY_STATIC_NAME     ssl.lib)
    set(CRYPTO_LIBRARY_STATIC_NAME  crypto.lib)

else()
    set(SSL_LIBRARY_STATIC_NAME     libssl.a)
    set(CRYPTO_LIBRARY_STATIC_NAME  libcrypto.a)
endif()

# find ssl static library
find_library(SSL_LIBRARY_STATIC     NAMES ${SSL_LIBRARY_STATIC_NAME}
    PATHS ${SSL_DIR}
    PATH_SUFFIXES lib64 lib build/ssl build/ssl/${CMAKE_BUILD_TYPE}
    NO_DEFAULT_PATH)

# find crypto static library
find_library(CRYPTO_LIBRARY_STATIC  NAMES ${CRYPTO_LIBRARY_STATIC_NAME}
    PATHS ${SSL_DIR}
    PATH_SUFFIXES lib64 lib build/crypto build/crypto/${CMAKE_BUILD_TYPE}
    NO_DEFAULT_PATH)

include (FindPackageHandleStandardArgs)
if(SSL_DYNAMIC)
    find_package_handle_standard_args(SSL
        REQUIRED_VARS
        SSL_INCLUDE_DIR
        SSL_LIBRARY
        CRYPTO_LIBRARY
    )
else()
    find_package_handle_standard_args(SSL
        REQUIRED_VARS
        SSL_INCLUDE_DIR
        SSL_LIBRARY_STATIC
        CRYPTO_LIBRARY_STATIC
    )
endif()

set (SSL_LIBRARIES
    ${SSL_LIBRARY}
    ${CRYPTO_LIBRARY})
set (SSL_LIBRARIES_STATIC
    ${SSL_LIBRARY_STATIC}
    ${CRYPTO_LIBRARY_STATIC})

mark_as_advanced(SSL_INCLUDE_DIR SSL_LIBRARIES SSL_LIBRARIES_STATIC)
