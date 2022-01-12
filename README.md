# XQUIC
<img src="docs/images/xquic_logo.png" alt="xquic logo"/>

> [简体中文文档 README-Zh-CN](./docs/docs-zh/README-zh.md)

## Introduction

XQUIC Library released by Alibaba is …

… **a client and server implementation of QUIC and HTTP/3 as specified by the IETF.** Currently supported QUIC versions are v1 and draft-29.

… **OS and platform agnostic.** It currently supports Android, iOS, Linux and macOS. Most of the code is used in our own products, and has been tested at scale on android, iOS apps, as well as servers.

… **still in active development.** [Interoperability](https://interop.seemann.io/) is regularly tested with other QUIC implementations.

## Requirements

To build XQUIC, you need 
* CMake
* BoringSSL or BabaSSL

To run test cases, you need
* libevent
* CUnit

## QuickStart Guide

xquic supports both BabaSSL and Boringssl.

### Build with BabaSSL

```bash
# get xquic source code
git clone git@github.com:alibaba/xquic.git
cd xquic

# get and build babassl
git clone git@github.com:BabaSSL/BabaSSL.git ./third_party/babassl
cd ./third_party/babassl/
./config --prefix=/usr/local/babassl
make -j
SSL_TYPE_STR="babassl"
SSL_PATH_STR="${PWD}"
SSL_INC_PATH_STR="${PWD}/include"
SSL_LIB_PATH_STR="${PWD}/libssl.a;${PWD}/libcrypto.a"
cd -

# build xquic with BabaSSL
git submodule update --init --recursive
mkdir -p build; cd build
cmake -DGCOV=on -DCMAKE_BUILD_TYPE=Debug -DXQC_ENABLE_TESTING=1 -DXQC_SUPPORT_SENDMMSG_BUILD=1 -DXQC_ENABLE_EVENT_LOG=1 -DXQC_ENABLE_BBR2=1 -DXQC_DISABLE_RENO=0 -DSSL_TYPE=${SSL_TYPE_STR} -DSSL_PATH=${SSL_PATH_STR} -DSSL_INC_PATH=${SSL_INC_PATH_STR} -DSSL_LIB_PATH=${SSL_LIB_PATH_STR} ..
make -j
```

### Build with BoringSSL

```bash
# get xquic source code
git clone git@github.com:alibaba/xquic.git
cd xquic

# get and build boringssl
git clone git@github.com:google/boringssl.git ./third_party/boringssl
cd ./third_party/boringssl
mkdir -p build && cd build
cmake -DBUILD_SHARED_LIBS=0 -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC" ..
make ssl crypto
cd ..
SSL_TYPE_STR="boringssl"
SSL_PATH_STR="${PWD}"
SSL_INC_PATH_STR="${PWD}/include"
SSL_LIB_PATH_STR="${PWD}/build/ssl/libssl.a;${PWD}/build/crypto/libcrypto.a"
cd ../..

# build xquic with BoringSSL
git submodule update --init --recursive
mkdir -p build; cd build
cmake -DGCOV=on -DCMAKE_BUILD_TYPE=Debug -DXQC_ENABLE_TESTING=1 -DXQC_SUPPORT_SENDMMSG_BUILD=1 -DXQC_ENABLE_EVENT_LOG=1 -DXQC_ENABLE_BBR2=1 -DXQC_DISABLE_RENO=0 -DSSL_TYPE=${SSL_TYPE_STR} -DSSL_PATH=${SSL_PATH_STR} -DSSL_INC_PATH=${SSL_INC_PATH_STR} -DSSL_LIB_PATH=${SSL_LIB_PATH_STR} ..
make -j
```

### Run testcases

```bash
sh ../scripts/xquic_test.sh
```

## Documentation

* For using the API, see the [API docs](./docs/API.md).
* For platform support details, see the [Platforms docs](./docs/Platforms.md).
* For Chinese (zh-cn) translation of the IETF QUIC Protocol, see the Translation docs.
    - The following translation is based on draft-34 and RFC Translation is Working In Progress.
    - [draft-ietf-quic-invariants-13-zh](./docs/translation/draft-ietf-quic-invariants-13-zh.md)
    - [draft-ietf-quic-transport-34-zh](./docs/translation/draft-ietf-quic-transport-34-zh.md)
    - [draft-ietf-quic-recovery-34-zh](./docs/translation/draft-ietf-quic-recovery-34-zh.md)
    - [draft-ietf-quic-tls-34-zh](./docs/translation/draft-ietf-quic-tls-34-zh.md)
    - [draft-ietf-quic-http-34-zh](./docs/translation/draft-ietf-quic-http-34-zh.md)
    - [draft-ietf-quic-qpack-21-zh](./docs/translation/draft-ietf-quic-qpack-21-zh.md)

* For other frequently asked questions, see the [FAQs](./docs/FAQ.md).

## Contributing

We would love for you to contribute to XQUIC and help make it even better than it is today! All types of contributions are encouraged and valued. Thanks to [all contributors](https://github.com/alibaba/xquic/blob/main/CONTRIBUTING.md#all-contributors). See our [Contributing Guidelines](./CONTRIBUTING.md) for more information.

If you have any questions, please feel free to open a new Discussion topic in our [discussion forums](https://github.com/alibaba/xquic/discussions).

## License

XQUIC is released under the Apache 2.0 License.

## Contact Us

Feel free to contact us in the following ways:

* e-mail: xquic@alibaba-inc.com
* Dingtalk group: 34059705
* slack channel: #xquic in quicdev group

  <img src="docs/images/dingtalk_group.jpg" width=200 alt="dingtalk group"/>
