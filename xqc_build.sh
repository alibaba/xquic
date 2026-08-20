# Copyright (c) 2022, Alibaba Group Holding Limited
#!/bin/sh

android_archs=(armeabi-v7a arm64-v8a)
ios_archs=(armv7 arm64 x86_64)
hmos_archs=(arm64-v8a)
CMAKE_CMD="cmake"
cur_dir=$(cd "$(dirname "$0")";pwd)

platform=$1
build_dir=$2
artifact_dir=$3

# boringssl is used as default
ssl_type="boringssl"

# The root CMakeLists falls back to find_package(SSL) when SSL_INC_PATH and
# SSL_LIB_PATH are both unset. Cross-compiling toolchains set
# CMAKE_FIND_ROOT_PATH_MODE_{INCLUDE,LIBRARY}=ONLY, which confines find_path and
# find_library to the sysroot and makes that discovery impossible, so both paths
# have to be supplied here for CMake to merely EXISTS-check them.
ssl_inc_path=$4
ssl_lib_path=$5

# Optional, appended to CMAKE_C_FLAGS. Use it for macros the build has to define
# but CMake has no switch for, such as -DBORINGSSL_PREFIX=<prefix> when linking a
# BoringSSL whose symbols were prefixed to keep them from clashing with the system
# libssl. Its symbol_prefix_include headers come in through ssl_inc_path.
extra_c_flags=$6

if [ -z "$ssl_inc_path" ] || [ -z "$ssl_lib_path" ] ; then
    echo "usage: $0 <platform> <build_dir> <artifact_dir> <ssl_inc_path> <ssl_lib_path> [extra_c_flags]"
    echo "  ssl_inc_path:  directory holding openssl/ssl.h"
    echo "  ssl_lib_path:  semicolon-separated libs, for example"
    echo "                 /path/to/libssl.a;/path/to/libcrypto.a"
    echo "  extra_c_flags: optional, appended to CMAKE_C_FLAGS, for example"
    echo "                 \"-DBORINGSSL_PREFIX=bs\""
    exit 1
fi

if [ ! -d "$ssl_inc_path" ] ; then
    echo "ssl include directory not exists: $ssl_inc_path"
    exit 1
fi

create_dir_force() {
    if [ x"$2" == x ] ; then
        echo "$1 MUST NOT be empty"
        exit 1
    fi
    if [ -d $2 ] ; then
        rm -rf $2
    fi
    mkdir $2
    echo "create $1 directory($2) suc"
}

platform=$(echo $platform | tr A-Z a-z )

# Shared by every platform. Keep one flag per line: $configures is expanded
# unquoted below, and the newline is what stops SSL_LIB_PATH's ';' from running
# into the flag that follows it.
common_configures="-DSSL_TYPE=${ssl_type}
                -DSSL_INC_PATH=${ssl_inc_path}
                -DSSL_LIB_PATH=${ssl_lib_path}
                -DCMAKE_BUILD_TYPE=Minsizerel
                -DXQC_ENABLE_TESTING=OFF
                -DGCOV=OFF
                -DXQC_ENABLE_RENO=OFF
                -DXQC_ENABLE_BBR2=ON
                -DXQC_ENABLE_COPA=OFF
                -DXQC_ENABLE_UNLIMITED=OFF
                -DXQC_ENABLE_MP_INTEROP=OFF
                -DXQC_DISABLE_LOG=OFF
                -DXQC_ONLY_ERROR_LOG=ON
                -DXQC_COMPAT_GENERATE_SR_PKT=ON"

if [ x"$platform" == xios ] ; then
    if [ x"$IOS_CMAKE_TOOLCHAIN" == x ] ; then
        echo "IOS_CMAKE_TOOLCHAIN MUST be defined"
        exit 0
    fi

    archs=${ios_archs[@]}
    configures="${common_configures}
                -DCMAKE_TOOLCHAIN_FILE=${IOS_CMAKE_TOOLCHAIN}
                -DDEPLOYMENT_TARGET=10.0
                -DENABLE_BITCODE=OFF"

elif [ x"$platform" == xandroid ] ; then
    if [ x"$ANDROID_NDK" == x ] ; then
        echo "ANDROID_NDK MUST be defined"
        exit 0
    fi

    archs=${android_archs[@]}
    configures="${common_configures}
                -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake
                -DANDROID_STL=c++_shared
                -DANDROID_NATIVE_API_LEVEL=android-19"

elif [ x"$platform" == xharmony ] ; then
    if [ x"$HMOS_CMAKE_TOOLCHAIN" == x ] ; then
        echo "HMOS_CMAKE_TOOLCHAIN MUST be defined"
        exit 0
    fi
    echo "HMOS_CMAKE_TOOLCHAIN: ${HMOS_CMAKE_TOOLCHAIN}"

    if [ x"$HMOS_CMAKE_PATH" == x ] ; then
        echo "HMOS_CMAKE_PATH MUST be defined"
        exit 0
    fi
    echo "HMOS_CMAKE_PATH: ${HMOS_CMAKE_PATH}"
    CMAKE_CMD=${HMOS_CMAKE_PATH}

    archs=${hmos_archs[@]}
    configures="${common_configures}
                -DCMAKE_TOOLCHAIN_FILE=${HMOS_CMAKE_TOOLCHAIN}
                -DDISABLE_WARNINGS=ON"
else
    echo "no support platform"
    exit 0
fi


generate_plat_spec() {
    plat_spec=
    if [ x"$platform" == xios ] ; then
        plat_spec="-DARCHS=$1"
        if [ x"$1" == xx86_64 ] ; then
            plat_spec="$plat_spec -DPLATFORM=SIMULATOR64"
        elif [ x"$1" == xi386 ] ; then
            plat_spec="$plat_spec -DPLATFORM=SIMULATOR"
        fi
    elif [ x"$platform" == xharmony ] ; then
        plat_spec="-DOHOS_ARCH=$1"
    else
        plat_spec="-DANDROID_ABI=$1"
    fi
    echo $plat_spec
}

create_dir_force build $build_dir
# to absoulute path 
build_dir=$cur_dir/$build_dir

create_dir_force artifact $artifact_dir
artifact_dir=$cur_dir/$artifact_dir

cd $build_dir 

for i in ${archs[@]} ;
do
    rm -f  CMakeCache.txt
    rm -rf CMakeFiles
    rm -rf Makefile
    rm -rf cmake_install.cmake
    rm -rf include
    rm -rf outputs
    rm -rf third_party

    echo "compiling xquic on $i arch"
    # extra_c_flags is quoted as a single argument, since it may hold several
    # space-separated flags and $configures is expanded unquoted.
    "${CMAKE_CMD}"  $configures  $(generate_plat_spec $i ) \
        ${extra_c_flags:+"-DCMAKE_C_FLAGS=$extra_c_flags"} \
        -DLIBRARY_OUTPUT_PATH=`pwd`/outputs/ ..
    make -j 4
    if [ $? != 0 ] ; then
        exit 0
    fi

    if [ ! -d  ${artifact_dir}/$i ] ; then
        mkdir -p ${artifact_dir}/$i
    fi
    # Copy whatever the platform produced. An unmatched glob is passed through
    # verbatim by the shell, so guard each name: iOS builds .dylib rather than
    # .so, and cp would otherwise complain about a file called "*.so".
    for lib in `pwd`/outputs/*.a `pwd`/outputs/*.so `pwd`/outputs/*.dylib ; do
        if [ -f "$lib" ] ; then
            cp -f "$lib" ${artifact_dir}/$i/
        fi
    done
done


make_fat() {
    lib_name=$1
    lipo_args=
    for i in ${archs[@]} ;
    do
        lipo_args="$lipo_args -arch $i $artifact_dir/$i/$lib_name"
    done

    # Run lipo directly. The old form was $($script), which executed lipo's
    # output as a command instead of reporting it, so failures went unnoticed.
    if ! lipo -create $lipo_args -output "$cur_dir/ios/xquic/xquic/Libs/$lib_name" ; then
        echo "lipo failed for $lib_name"
        exit 1
    fi
}


if [ x"$platform" == xios ] ; then
    if [ ! -d $cur_dir/ios/xquic/xquic/Headers ] ; then
        mkdir -p $cur_dir/ios/xquic/xquic/Headers
    fi
    if [ ! -d $cur_dir/ios/xquic/xquic/Libs ] ; then
        mkdir -p $cur_dir/ios/xquic/xquic/Libs
    fi
    make_fat libxquic-static.a
    make_fat libcrypto.a
    make_fat libssl.a
    cp -f $cur_dir/include/xquic/*   $cur_dir/ios/xquic/xquic/Headers/
    cp -f $build_dir/include/xquic/* $cur_dir/ios/xquic/xquic/Headers/

fi


