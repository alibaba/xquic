# XQUIC

## 简介

阿里巴巴发布的XQUIC库

* **是一个遵循IETF标准的QUIC和HTTP/3的客户端和服务端实现。** 目前支持的QUIC版本是v1和draft-29。

* **是跨平台的。** 目前支持Android、iOS、Linux和macOS。绝大部分代码被用于我们自己的产品，并已在安卓、iOS APP以及服务端上进行了大规模测试。

* **目前仍在积极开发中。** 我们定期与其他QUIC实现进行[互通性测试](https://interop.seemann.io/)。

## 依赖

编译XQUIC，你需要：
* CMake
* BoringSSL 或者 BabaSSL

运行测试用例，你需要：
* libevent
* CUnit

## 快速入门指南

XQUIC 支持 BoringSSL 和 BabaSSL。

### 使用 BabaSSL 编译

```bash
# 获取 XQUIC 源码
git clone git@github.com:alibaba/xquic.git
cd xquic

# 编译 BabaSSL
git clone git@github.com:BabaSSL/BabaSSL.git ./third_party/babassl
cd ./third_party/babassl/
./config --prefix=/usr/local/babassl
make -j
SSL_TYPE_STR="babassl"
SSL_PATH_STR="${PWD}"
SSL_INC_PATH_STR="${PWD}/include"
SSL_LIB_PATH_STR="${PWD}/libssl.a;${PWD}/libcrypto.a"
cd -

# 使用 BabaSSL 编译 XQUIC
git submodule update --init --recursive
mkdir -p build; cd build
cmake -DGCOV=on -DCMAKE_BUILD_TYPE=Debug -DXQC_ENABLE_TESTING=1 -DXQC_SUPPORT_SENDMMSG_BUILD=1 -DXQC_ENABLE_EVENT_LOG=1 -DXQC_ENABLE_BBR2=1 -DXQC_DISABLE_RENO=0 -DSSL_TYPE=${SSL_TYPE_STR} -DSSL_PATH=${SSL_PATH_STR} -DSSL_INC_PATH=${SSL_INC_PATH_STR} -DSSL_LIB_PATH=${SSL_LIB_PATH_STR} ..
make -j
```

### 使用 BoringSSL 编译

```bash
# 获取 XQUIC 源码
git clone git@github.com:alibaba/xquic.git
cd xquic

# 编译 BoringSSL
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

# 使用 BoringSSL 编译 XQUIC
git submodule update --init --recursive
mkdir -p build; cd build
cmake -DGCOV=on -DCMAKE_BUILD_TYPE=Debug -DXQC_ENABLE_TESTING=1 -DXQC_SUPPORT_SENDMMSG_BUILD=1 -DXQC_ENABLE_EVENT_LOG=1 -DXQC_ENABLE_BBR2=1 -DXQC_DISABLE_RENO=0 -DSSL_TYPE=${SSL_TYPE_STR} -DSSL_PATH=${SSL_PATH_STR} -DSSL_INC_PATH=${SSL_INC_PATH_STR} -DSSL_LIB_PATH=${SSL_LIB_PATH_STR} ..
make -j
```

### 运行测试用例

```bash
sh ../scripts/xquic_test.sh
```

## 文档

* 关于API的使用，详见 [API文档](../../docs/API.md)。
* 关于平台支持的细节，详见 [平台文档](../../docs/Platforms.md)。
* 关于 IETF QUIC Protocol 的中文翻译，详见翻译文档。
    - 以下翻译均基于 draft-34，RFC的翻译工作正在进行中。
    - [draft-ietf-quic-invariants-13-zh](../../docs/translation/draft-ietf-quic-invariants-13-zh.md)
    - [draft-ietf-quic-transport-34-zh](../../docs/translation/draft-ietf-quic-transport-34-zh.md)
    - [draft-ietf-quic-recovery-34-zh](../../docs/translation/draft-ietf-quic-recovery-34-zh.md)
    - [draft-ietf-quic-tls-34-zh](../../docs/translation/draft-ietf-quic-tls-34-zh.md)
    - [draft-ietf-quic-http-34-zh](../../docs/translation/draft-ietf-quic-http-34-zh.md)
    - [draft-ietf-quic-qpack-21-zh](../../docs/translation/draft-ietf-quic-qpack-21-zh.md)
* 关于event_log模块的使用, 详见 [Event_log module docs](./docs/docs-zh/Event_log-zh.md)。
* 关于测试，参见 [测试文档](./docs/docs-zh/Testing-zh.md)。
* 关于常见问题，参见 [FAQs](./docs/docs-zh/FAQ-zh.md) 和 [Trouble Shooting Guide](./docs/docs-zh/Troubleshooting-zh.md)。

## Contributing

我们希望你能为XQUIC做出贡献，帮助它变得比现在更好！我们鼓励并重视所有类型的贡献，请参阅我们的[贡献指南](./CONTRIBUTING-zh.md)了解更多信息。

如果你有任何问题，请随时在我们的[讨论区](https://github.com/alibaba/xquic/discussions)开启一个新的讨论主题。

## License

XQUIC 使用 Apache 2.0 许可证。
