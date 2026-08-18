# Platforms docs

XQUIC currently supports `Android` , `iOS` , `HarmonyOS` , `Linux` , `macOS` and `Windows` .

## Android/iOS/HarmonyOS Compile Script

Use [`xqc_mobile_build.sh`](../xqc_mobile_build.sh) to build XQUIC for Android,
iOS, or HarmonyOS. This helper is only for mobile builds; use the
[README build instructions](../README.md#quickstart-guide) for Linux and
macOS.

```bash
./xqc_mobile_build.sh ios|android|harmony \
    <build_dir> <artifact_dir> [ssl_path]
```

If `ssl_path` is omitted, the helper uses `third_party/boringssl`.

Set `IOS_CMAKE_TOOLCHAIN` for iOS, `ANDROID_NDK` for Android, or both
`HMOS_CMAKE_PATH` and `HMOS_CMAKE_TOOLCHAIN` for HarmonyOS before running the
helper. The old `xqc_build.sh` entry point remains as a deprecated
compatibility wrapper.

## Linux Release

The default `CMAKE_BUILD_TYPE` is `Release` , so you only need to compile BoringSSL or BabaSSL, and then build XQUIC.

```bash
# build XQUIC with BabaSSL
git submodule update --init --recursive
mkdir build; cd build
cmake ..
make -j

# build XQUIC with BoringSSL
git submodule update --init --recursive
mkdir build; cd build
cmake -DSSL_TYPE=${SSL_TYPE_STR} -DSSL_PATH=${SSL_PATH_STR} -DSSL_INC_PATH=${SSL_INC_PATH_STR} -DSSL_LIB_PATH=${SSL_LIB_PATH_STR} ..
make -j
```

## macOS Release

You can use the cmake variables `-DPLATFORM=mac` to build XQUIC on macOS.

Remember you still need to install BoringSSL or Tongsuo(BabaSSL) first, please follow to the guidance [get and build BoringSSL](https://github.com/alibaba/xquic#build-with-boringssl) / [get and build BabaSSL](https://github.com/alibaba/xquic#build-with-babassl).

```bash

# build XQUIC with BoringSSL

git submodule update --init --recursive
mkdir build; cd build
cmake -DPLATFORM=mac -DSSL_TYPE=${SSL_TYPE_STR} -DSSL_PATH=${SSL_PATH_STR} -DSSL_INC_PATH=${SSL_INC_PATH_STR} -DSSL_LIB_PATH=${SSL_LIB_PATH_STR} -DXQC_SUPPORT_SENDMMSG_BUILD=0 ..
make -j


# build XQUIC with BabaSSL
git submodule update --init --recursive
mkdir build; cd build
cmake -DPLATFORM=mac -DXQC_SUPPORT_SENDMMSG_BUILD=0 ..
make -j

```

Troubleshooting:
> Note: sendmmsg is not supported on MacOS, make sure you add -DXQC\_SUPPORT\_SENDMMSG\_BUILD=0 to turn off the feature 

## Windows Release

```bash
Warning: Versions that support Windows platform: v1.1.0 ～ v1.3.0.
XQUIC v1.4.0 does not support Windows platform temporarily, it is expected to restore in v1.5.0.
```

xquic possible dependencies for Windows: Perl, Go, BoringSSL, libevent, set after installation to set the corresponding program PATH to the $PATH environment variable

* install GO： https://go.dev/dl/
* install cmake：https://cmake.org/download/
* install NASM ：https://www.nasm.us/ （boringssl build need）
* install vcpkg：https://github.com/Microsoft/vcpkg

```bash
VCPKG_DEFAULT_TRIPLET=x64-windows-static

#install libevent
vcpkg install libevent:x64-windows-static
```

build XQUIC

```bash
# step 1: get sourcecode
git clone https://github.com/alibaba/xquic.git
cd xquic
git submodule update --init --recursive

# step 2：build boringssl
git clone https://github.com/google/boringssl.git ./third_party/boringssl
cd ./third_party/boringssl
mkdir build
cd build

cmake  -DCMAKE_GENERATOR_PLATFORM=x64 --config Debug -DBUILD_SHARED_LIBS=0 -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC" ..

# build ssl && crypto
MSBuild.exe ALL_BUILD.vcxproj

cd ../../../

# step 3：build xquic
mkdir build
cd build
cmake -DSSL_TYPE=${SSL_TYPE_STR} -DSSL_PATH=${SSL_PATH_STR} ..

MSBuild.exe xquic.vcxproj

# build demo && test
#eg: cmake -DEVENT_LIB_DIR=D:/project/vcpkg/packages/libevent_x64-windows-static ..
cmake -DXQC_ENABLE_TESTING=1 -DLIBEVENT_DIR=your_event_path ..

MSBuild.exe demo_client.vcxproj
MSBuild.exe demo_server.vcxproj
MSBuild.exe test_client.vcxproj
MSBuild.exe test_server.vcxproj
```
