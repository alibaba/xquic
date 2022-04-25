# Platforms docs

XQUIC currently supports `Android` , `iOS` , `Linux` and `macOS` .

## Android/iOS Compile Script

The Android and iOS use `.so` files, there is a [ `xqc_build.sh` ](../xqc_build.sh) script in the XQUIC library directory, execute the script to compile to complete the corresponding compilation.

```bash
sh xqc_build.sh ios/android <build_dir> <artifact_dir>
```

> Note: You need to specify the IOS/android build toolchain before compiling, download and set the environment variable IOS_CMAKE_TOOLCHAIN or ANDROID_NDK, or directly modify CMAKE_TOOLCHAIN_FILE in `xqc_build.sh` .

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

```bash
# build XQUIC with BabaSSL
git submodule update --init --recursive
mkdir build; cd build
cmake -DPLATFORM=mac ..
make -j

# build XQUIC with BoringSSL
git submodule update --init --recursive
mkdir build; cd build
cmake -DPLATFORM=mac -DSSL_TYPE=${SSL_TYPE_STR} -DSSL_PATH=${SSL_PATH_STR} -DSSL_INC_PATH=${SSL_INC_PATH_STR} -DSSL_LIB_PATH=${SSL_LIB_PATH_STR} ..
make -j
```

## Windows Release (beta)

windows平台下编译xquic的依赖项 ：Perl，Go，boringssl，libevent，安装好后设置将对应程序路径设置到 $PATH 环境变量，编译命令行执行建议在powershell 下进行

* 安装GO： https://go.dev/dl/
* 安装cmake：https://cmake.org/download/
* 安装NASM ：https://www.nasm.us/ （boringssl windows编译需要）
* 安装windows包管理器vcpkg：https://github.com/Microsoft/vcpkg

```bash
VCPKG_DEFAULT_TRIPLET=x64-windows-static

#安装libevent
vcpkg install libevent:x64-windows-static
```

编译XQUIC

```bash
# step 1: 拉取代码仓库
git clone git@github.com:alibaba/xquic.git
cd xquic
git submodule update --init --recursive

# step 2：编译boringssl
git clone git@github.com:google/boringssl.git ./third_party/boringssl
cd ./third_party/boringssl
mkdir build
cd build

cmake  -DCMAKE_GENERATOR_PLATFORM=x64 --config Debug -DBUILD_SHARED_LIBS=0 -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC" ..

# 编译 ssl && crypto
MSBuild.exe ALL_BUILD.vcxproj
# 退回到xquic
cd ../../../


# step 3：编译xquic
mkdir build
cd build
cmake -DSSL_TYPE=${SSL_TYPE_STR} -DSSL_PATH=${SSL_PATH_STR} -DSSL_INC_PATH=${SSL_INC_PATH_STR} -DSSL_LIB_PATH=${SSL_LIB_PATH_STR} ..

MSBuild.exe xquic.vcxproj

# 编译demo && test
#eg: cmake -DEVENT_LIB_DIR=D:/project/vcpkg/packages/libevent_x64-windows-static ..
cmake -DEVENT_LIB_DIR=your_event_path ..
MSBuild.exe demo_client.vcxproj
MSBuild.exe demo_server.vcxproj
MSBuild.exe test_client.vcxproj
MSBuild.exe test_server.vcxproj
```
