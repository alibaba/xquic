cmake_minimum_required(VERSION 3.10.2)
project("xquicandroiddemo")

SET(CMAKE_C_FLAGS_DEBUG "-g -std=c11")
SET(CMAKE_CXX_FLAGS_DEBUG "-g -std=c++11")

# 包含头文件
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include/libev)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include/xquic)

link_directories(${CMAKE_CURRENT_SOURCE_DIR}/share_libs/${CMAKE_ANDROID_ARCH_ABI})
link_libraries("libxquic.so")

aux_source_directory(. SRC_NATIVE)
aux_source_directory(./src SRC_XQC)

add_library( # Sets the name of the library.
             native-lib

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
             ${SRC_NATIVE} ${SRC_XQC} src/libev/ev.c src/libev/event.c)


find_library( # Sets the name of the path variable.
              log-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              log )


target_link_libraries( # Specifies the target library.
                       native-lib

                       # Links the target library to the log library
                       # included in the NDK.
                       ${log-lib} )
