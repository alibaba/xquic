# Features

## 支持的 TLS 1.3 加密套件

XQUIC 支持以下 TLS 1.3 加密套件用于 QUIC 数据包保护，具体参见 [RFC 9001 第 5 节](https://www.rfc-editor.org/rfc/rfc9001#section-5)：

| 加密套件 | AEAD 算法 | 头部保护 | 状态 |
|---|---|---|---|
| TLS_AES_128_GCM_SHA256 | AEAD_AES_128_GCM | AES-ECB (128-bit) | 支持 |
| TLS_AES_256_GCM_SHA384 | AEAD_AES_256_GCM | AES-ECB (256-bit) | 支持 |
| TLS_CHACHA20_POLY1305_SHA256 | AEAD_CHACHA20_POLY1305 | ChaCha20 | 支持 |
| TLS_AES_128_CCM_SHA256 | AEAD_AES_128_CCM | — | 不支持 |
| TLS_AES_128_CCM_8_SHA256 | — | — | 不支持 |

默认加密套件列表由 `include/xquic/xquic.h` 中的 `XQC_TLS_CIPHERS` 宏定义：

```
TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
```

### 为什么不支持 CCM

XQUIC 不支持基于 CCM 的加密套件（`TLS_AES_128_CCM_SHA256` 和 `TLS_AES_128_CCM_8_SHA256`），原因如下：

1. **RFC 9001 中为可选项**：QUIC 实现不强制要求支持 CCM。
2. **安全限值极低**：AEAD_AES_128_CCM 的机密性和完整性限值仅为 2^21.5（约 2,992,530 个数据包），远低于 GCM（机密性：2^23，完整性：2^52）和 ChaCha20-Poly1305（机密性：2^62，完整性：2^36）。这意味着需要更频繁地进行密钥更新。
3. **CCM_8 无头部保护方案**：RFC 9001 未为 `TLS_AES_128_CCM_8_SHA256` 定义头部保护方案，因此无法在 QUIC 中使用。
4. **行业共识**：大多数 QUIC 实现（包括 ngtcp2、quiche）也不支持 CCM。

## qlog
基于 qlog ([draft-ietf-quic-qlog-main-schema](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-main-schema/)、[draft-ietf-quic-qlog-quic-events](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-quic-events/) 和 [draft-ietf-quic-qlog-h3-events](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-h3-events/))，xquic 实现了 quic 事件记录。
### 编译参数 DXQC_ENABLE_EVENT_LOG 开启 qlog
```shell
cd build
rm -rf * 
# 添加 "-DXQC_ENABLE_EVENT_LOG=1" 参数
cmake -DGCOV=on -DCMAKE_BUILD_TYPE=Debug -DXQC_ENABLE_TESTING=1 -DXQC_SUPPORT_SENDMMSG_BUILD=1 -DXQC_ENABLE_EVENT_LOG=1 -DXQC_ENABLE_BBR2=1 -DXQC_ENABLE_RENO=1 -DSSL_TYPE=${SSL_TYPE_STR} -DSSL_PATH=${SSL_PATH_STR} ..

make -j
```
### 运行测试
按重要性，qlog 将事件分为 core、base、extra 三个 importance level，可以通过 --qlog_importance 设置：
```shell
./tests/test_server -l e -e --qlog_importance extra

./tests/test_client -s 10240 -l e -t 1 -E --qlog_importance extra
```

通过 --qlog_disable 关闭 qlog：
```shell
./tests/test_server -l e -e --qlog_disable

./tests/test_client -s 10240 -l e -t 1 -E --qlog_disable
```

### JSON 格式转换
执行 qlog_parser.py 脚本工具，将 xquic log 转换 json 格式 qlog.
```shell
python ../scripts/qlog_parser.py --clog clog --slog slog --qlog_path demo_qlog.json
```


