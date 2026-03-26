# 基于 xquic 实现通用 WebTransport 库 + Python 接口完整方案

> 作者：xquic team | 日期：2026-03-24 | 状态：Draft

---

## 1. 背景与现状分析

### 1.1 xquic 已有的 WebTransport 基础

xquic 已经具备 WebTransport over HTTP/3 的核心基础设施（位于 `moq_draft_14_dev_webtransport` 分支，commit `a36cfdbe`），包括：

| 模块 | 文件 | 功能 |
|------|------|------|
| Context | `xqc_webtransport_ctx.c/h` | 引擎级 WT 上下文，注册 H3 回调 |
| Connection | `xqc_webtransport_conn.c/h` | WT 连接管理，session 注册表 |
| Session | `xqc_webtransport_session.c/h` | 基于 Extended CONNECT 的 session |
| Stream | `xqc_webtransport_stream.c/h` | Bidi/Uni stream 创建、读写、关闭 |
| Datagram | `xqc_webtransport_dgram.c/h` | 基于 QUIC DATAGRAM 的不可靠传输 |
| Wire | `xqc_webtransport_wire.c/h` | Session ID 变长整数编解码 |
| Request | `xqc_webtransport_request.c/h` | HTTP 头部表解析（:method, :protocol 等）|
| Defs | `xqc_webtransport_defs.c/h` | 常量定义 |
| Public API | `include/xquic/xqc_webtransport.h` | 497 行公共 API 头文件 |
| Demo Server | `src/webtransport/wt_demo_server.c` | Echo 服务器 |
| Browser Test | `demo/webtransport_echo_test.html` | Chrome WebTransport 测试页 |

总计约 **5500 行 C 代码**。

### 1.2 已验证的互通结果（2026-03）

| 对端 | 测试内容 | 结果 |
|------|---------|------|
| Chrome 97+ | Bidi/Uni stream echo | PASS |
| moq-dev/moq (Rust) relay | MoQ SETUP over WT | PASS |
| Meta moxygen (fb.mvfst.net) | MoQ SETUP over WT | PASS* |

*moxygen 服务偶尔不稳定。

### 1.3 当前存在的问题

1. **代码未在主线**：WT 代码从当前 HEAD 被移除，仅存在于历史分支
2. **H3 SETTINGS 未正式集成**：WebTransport 相关 SETTINGS（`ENABLE_WEBTRANSPORT`、`H3_DATAGRAM`、`ENABLE_CONNECT_PROTOCOL`）在 WT ctx 中硬编码，未集成到 H3 核心层的 `xqc_h3_conn_settings_t`
3. **无 Python 绑定**：没有任何 Python 接口
4. **部分互通问题**：MoQ 层消息类型编号不匹配（此为 MoQ 层问题，不影响 WT 层）

---

## 2. 开发基础

### 2.1 分支策略

**所有开发基于 `origin/main` 最新版本**（`1a7530cb`），创建独立的 feature 分支：

```bash
cd xquic
git fetch origin
git checkout -b feat/webtransport origin/main

# 从历史 commit 恢复已有的 WebTransport 文件
git checkout a36cfdbe -- \
    src/webtransport/ \
    include/xquic/xqc_webtransport.h \
    demo/xqc_webtransport.h

# 审查恢复的文件，确保和 origin/main 的 H3/QUIC 层兼容
# 可能需要适配 API 变更
```

### 2.2 为什么基于 origin/main

- 避免引入其他实验分支的不稳定代码（如 MoQ draft-17、delivery-feedback 等）
- `origin/main` 包含最新的 bugfix（SSL 路径修复、非法帧处理等）
- 更易于最终合并回主线

---

## 3. 实施计划

### 第一阶段：恢复和整合 WebTransport C 核心（~3天）

#### 3.1 恢复 `src/webtransport/` 目录

从 commit `a36cfdbe` 恢复 16 个源文件 + 公共头文件。

#### 3.2 将 WebTransport SETTINGS 集成到 H3 核心层

**目的**：让 H3 层原生支持 WebTransport 的 SETTINGS 协商，而非绕过。

需要修改的文件和内容：

**`src/http3/xqc_h3_defs.h`** — 添加 SETTINGS ID

```c
typedef enum {
    /* 现有的 */
    XQC_H3_SETTINGS_MAX_FIELD_SECTION_SIZE      = 0x06,
    XQC_H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY    = 0x01,
    XQC_H3_SETTINGS_QPACK_BLOCKED_STREAMS       = 0x07,

    /* WebTransport 新增 */
    XQC_H3_SETTINGS_ENABLE_CONNECT_PROTOCOL     = 0x08,
    XQC_H3_SETTINGS_H3_DATAGRAM                 = 0x33,
    XQC_H3_SETTINGS_ENABLE_WEBTRANSPORT         = 0x2b603742,
} xqc_h3_settings_id;
```

**`include/xquic/xqc_http3.h`** — `xqc_h3_conn_settings_t` 添加字段

```c
typedef struct xqc_h3_conn_settings_s {
    uint64_t max_field_section_size;
    uint64_t max_pushes;
    uint64_t qpack_enc_max_table_capacity;
    uint64_t qpack_dec_max_table_capacity;
    uint64_t qpack_blocked_streams;
#ifdef XQC_COMPAT_DUPLICATE
    xqc_bool_t qpack_compat_duplicate;
#endif

    /* WebTransport 新增 */
    xqc_bool_t enable_connect_protocol;   /* SETTINGS_ENABLE_CONNECT_PROTOCOL (0x08) */
    xqc_bool_t h3_datagram;              /* SETTINGS_H3_DATAGRAM (0x33) */
    xqc_bool_t enable_webtransport;      /* SETTINGS_ENABLE_WEBTRANSPORT (0x2b603742) */
} xqc_h3_conn_settings_t;
```

**`src/http3/frame/xqc_h3_frame.c`** — `xqc_h3_frm_write_settings()` 条件写入

```c
// 在现有的 3 个 settings 之后，条件添加：
if (setting->enable_webtransport) {
    settings[count].identifier.vi = XQC_H3_SETTINGS_ENABLE_CONNECT_PROTOCOL;
    settings[count].value.vi = 1;
    len += ...; ++count;

    settings[count].identifier.vi = XQC_H3_SETTINGS_H3_DATAGRAM;
    settings[count].value.vi = 1;
    len += ...; ++count;

    settings[count].identifier.vi = XQC_H3_SETTINGS_ENABLE_WEBTRANSPORT;
    settings[count].value.vi = 1;
    len += ...; ++count;
}
```

**`src/http3/xqc_h3_conn.c`** — `xqc_h3_conn_on_settings_entry_received()` 解析

```c
case XQC_H3_SETTINGS_ENABLE_CONNECT_PROTOCOL:
    h3c->peer_h3_conn_settings.enable_connect_protocol = (xqc_bool_t)value;
    break;
case XQC_H3_SETTINGS_H3_DATAGRAM:
    h3c->peer_h3_conn_settings.h3_datagram = (xqc_bool_t)value;
    break;
case XQC_H3_SETTINGS_ENABLE_WEBTRANSPORT:
    h3c->peer_h3_conn_settings.enable_webtransport = (xqc_bool_t)value;
    break;
```

#### 3.3 CMakeLists.txt 集成

```cmake
option(XQC_ENABLE_WEBTRANSPORT "enable webtransport" OFF)

if(XQC_ENABLE_WEBTRANSPORT)
    set(WEBTRANSPORT_SOURCES
        "src/webtransport/xqc_webtransport_session.c"
        "src/webtransport/xqc_webtransport_ctx.c"
        "src/webtransport/xqc_webtransport_defs.c"
        "src/webtransport/xqc_webtransport_dgram.c"
        "src/webtransport/xqc_webtransport_request.c"
        "src/webtransport/xqc_webtransport_stream.c"
        "src/webtransport/xqc_webtransport_conn.c"
        "src/webtransport/xqc_webtransport_wire.c"
    )
    # WEBTRANSPORT_SOURCES 会被追加到 libxquic 的源文件列表中
    add_subdirectory(src/webtransport)  # 构建 wt_test_server demo
endif()
```

#### 3.4 代码清理

- 移除 `wt_demo_server.c` 中的硬编码路径（`/Users/sy03/Desktop/...`）
- 将 `printf` 调试输出替换为 `xqc_log`
- 增加 `MAX_SETTING_ENTRY` 常量值（从 3 调整为 6+）

---

### 第二阶段：互通性修复和验证（~2天）

#### 4.1 RFC 合规性检查清单

WebTransport over HTTP/3 涉及以下标准：

| RFC/Draft | 内容 | xquic 支持状态 |
|-----------|------|---------------|
| RFC 9114 | HTTP/3 | 已支持 |
| RFC 9221 | QUIC Datagrams | 已支持 |
| RFC 9297 | HTTP Datagrams & Capsule Protocol | 部分（需补充 Capsule） |
| RFC 9220 | WebTransport over HTTP/3 | 核心已实现 |

关键合规点：

1. **SETTINGS 三件套**：服务端必须在 SETTINGS frame 中发送 `ENABLE_WEBTRANSPORT=1` + `H3_DATAGRAM=1` + `ENABLE_CONNECT_PROTOCOL=1`
2. **Extended CONNECT**：客户端发送 `:method=CONNECT :protocol=webtransport :path=/... :authority=host`
3. **Session ID**：WebTransport session 的 session_id = Extended CONNECT 请求所在的 QUIC stream ID
4. **WT Stream 前缀**：WebTransport 流的数据前必须写入 session_id（QUIC varint 编码）
5. **WT Uni Stream 类型字节**：0x54 (client→server) 作为 stream type byte
6. **WT Bidi Stream**：无额外 stream type byte，直接在 bidi stream 上写 session_id
7. **Capsule Protocol**：`CLOSE_WEBTRANSPORT_SESSION` (type=0x2843) capsule 用于优雅关闭（RFC 9297）

#### 4.2 互通验证矩阵

| 组合 | Client | Server | 验证内容 | 状态 |
|------|--------|--------|---------|------|
| Chrome-xquic | Chrome 97+ | xquic wt_test_server | bidi/uni/dgram echo | 已验证 |
| aioquic-xquic | aioquic client | xquic wt_test_server | bidi/uni/dgram echo | 待验证 |
| xquic-aioquic | xquic client | aioquic server | bidi/uni/dgram echo | 待验证 |
| moq-relay | xquic client | moq-dev/moq relay | WT session 建立 | 已验证 |
| xquic-xquic | Python client | Python server | 全功能 | 待开发 |

#### 4.3 验证步骤

```bash
# Chrome 互通验证
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout certs/localhost.key -out certs/localhost.crt \
    -days 14 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

cd build && make wt_test_server -j
./src/webtransport/wt_test_server  # 监听 127.0.0.1:4443

# Chrome 打开 demo/webtransport_echo_test.html
```

```bash
# aioquic 互通验证
pip install aioquic
# 用 aioquic 的 WebTransport 示例连接 xquic server
```

---

### 第三阶段：Python 封装 - pyxquic-wt（~5天）

#### 5.1 技术选型

| 方案 | 优势 | 劣势 | 结论 |
|------|------|------|------|
| **CFFI** | 直接解析 C 头文件；ABI/API 双模式；asyncio 友好 | 首次编译稍慢 | **选用** |
| ctypes | 纯 Python，无需编译 | 手动声明类型繁琐；回调管理复杂 | 不选 |
| pybind11 | C++ 绑定优秀 | xquic 是 C；引入 C++ 依赖 | 不选 |
| Cython | 性能好 | 学习成本高；维护成本高 | 不选 |

#### 5.2 包结构

```
python/
├── pyxquic_wt/
│   ├── __init__.py           # export WebTransportClient, WebTransportServer
│   ├── _ffi_build.py         # CFFI 编译定义（解析 xqc_webtransport.h）
│   ├── _ffi.py               # CFFI 加载和底层绑定
│   ├── client.py             # WebTransportClient（async context manager）
│   ├── server.py             # WebTransportServer（asyncio server）
│   ├── session.py            # WebTransportSession
│   ├── stream.py             # BidiStream, UniStream
│   ├── datagram.py           # Datagram 收发
│   └── _event_loop.py        # asyncio ↔ xquic 事件循环桥接
├── pyproject.toml            # 包元数据 + cibuildwheel 配置
├── setup.py                  # CFFI 集成
├── tests/
│   ├── test_echo.py          # 本地 echo 端到端测试
│   └── test_interop.py       # 与 aioquic 互通测试
└── examples/
    ├── echo_server.py        # 最简 echo server 示例
    ├── echo_client.py        # 最简 echo client 示例
    └── chat.py               # 简单聊天应用示例
```

#### 5.3 Python API 设计

##### 客户端

```python
import asyncio
from pyxquic_wt import WebTransportClient

async def main():
    # 创建连接（async context manager 自动管理生命周期）
    async with WebTransportClient("https://localhost:4443/echo") as client:
        # === 双向流 ===
        stream = await client.create_bidi_stream()
        await stream.send(b"Hello WebTransport!")
        data = await stream.recv()
        print(f"Echo: {data}")  # Echo: b'Hello WebTransport!'

        # === 单向流 ===
        uni = await client.create_uni_stream()
        await uni.send(b"One-way message", fin=True)

        # === 接收远端发起的流 ===
        async for incoming in client.incoming_bidi_streams():
            data = await incoming.recv()
            print(f"Server sent: {data}")

        # === Datagram（不可靠传输）===
        await client.send_datagram(b"Low-latency data")
        dgram = await client.recv_datagram()

asyncio.run(main())
```

##### 服务端

```python
import asyncio
from pyxquic_wt import WebTransportServer

async def handle_session(session):
    """每个 WebTransport session 的处理函数"""
    print(f"New session: path={session.path}, peer={session.remote_addr}")

    # Echo: 接收所有 bidi stream 并回显
    async for stream in session.incoming_bidi_streams():
        data = await stream.recv()
        await stream.send(data)  # echo back
        await stream.close()

async def main():
    server = WebTransportServer(
        host="0.0.0.0",
        port=4443,
        cert_file="certs/localhost.crt",
        key_file="certs/localhost.key",
    )
    server.on_session = handle_session
    print("WebTransport server listening on :4443")
    await server.serve_forever()

asyncio.run(main())
```

#### 5.4 事件循环桥接核心设计

xquic 是基于回调的事件驱动模型，需要桥接到 Python asyncio：

```
┌─────────────────────────────────────────────┐
│              Python asyncio loop            │
│                                             │
│  add_reader(udp_fd) ──► xqc_engine_packet() │
│  call_later(ms)     ──► xqc_engine_main()   │
│                                             │
│  Future.set_result() ◄── xquic callbacks    │
│    @ffi.callback("int(xqc_h3_conn_t*,...)")  │
└─────────────────────────────────────────────┘
```

关键点：
- 用 `loop.add_reader(udp_fd, on_udp_readable)` 监听 UDP socket
- xquic 的 timer 回调通过 `loop.call_later()` 调度
- xquic 的 stream/session/datagram 回调通过 `@ffi.callback` 注册，在回调内 `future.set_result()` 通知 Python 协程
- 整个 xquic engine 在 asyncio 事件循环线程中运行，天然线程安全

#### 5.5 需要补充的 C API

当前 `include/xquic/xqc_webtransport.h` 需要补充：

| 新 API | 用途 |
|--------|------|
| `xqc_wt_create_bidistream()` | 客户端创建双向流 |
| `xqc_wt_bidistream_recv()` | 从双向流接收数据 |
| `xqc_wt_unistream_recv()` | 从单向流接收数据 |
| `xqc_wt_session_set_user_data()` | 设置 session 用户数据 |
| `xqc_wt_session_get_user_data()` | 获取 session 用户数据 |
| 客户端 Extended CONNECT 发起 | 主动建立 WT session |

---

### 第四阶段：预编译 Wheel 分发（~3天）

#### 6.1 什么是预编译 Wheel

预编译 wheel（`.whl`）是 Python 的二进制分发格式。用户 `pip install` 时**无需编译器、无需 cmake、无需 SSL 库**，直接下载对应平台的预编译包即可。

```bash
# 用户的理想体验（最终目标）
pip install pyxquic-wt
python -c "from pyxquic_wt import WebTransportClient; print('OK')"
```

#### 6.2 构建矩阵

| 平台 | 架构 | Python 版本 | 总计 |
|------|------|------------|------|
| Linux (manylinux2014) | x86_64, aarch64 | 3.8 - 3.13 | 12 |
| macOS | x86_64 (Intel), arm64 (Apple Silicon) | 3.8 - 3.13 | 12 |
| Windows | x86_64 | 3.8 - 3.13 | 6 |
| **合计** | | | **~30 个 wheel** |

#### 6.3 构建工具：cibuildwheel

[cibuildwheel](https://cibuildwheel.readthedocs.io/) 是 Python 社区标准的跨平台 wheel 构建工具，被 numpy、scikit-learn、cryptography 等主流项目使用。

##### pyproject.toml 配置

```toml
[project]
name = "pyxquic-wt"
version = "0.1.0"
description = "WebTransport client/server powered by xquic QUIC/HTTP3 stack"
requires-python = ">=3.8"
dependencies = ["cffi>=1.15"]
license = {text = "Apache-2.0"}
classifiers = [
    "Programming Language :: Python :: 3",
    "Programming Language :: C",
    "Topic :: Internet :: WWW/HTTP",
    "Topic :: System :: Networking",
    "Framework :: AsyncIO",
]

[build-system]
requires = ["setuptools>=42", "cffi>=1.15", "wheel"]
build-backend = "setuptools.build_meta"

[tool.cibuildwheel]
# 在 wheel 构建前编译 xquic C 库
before-all = [
    "cd {project} && git submodule update --init --recursive",
    "cd {project}/third_party/babassl && ./config --prefix=$PWD/output && make -j$(nproc) && make install",
    "mkdir -p {project}/build_wheel && cd {project}/build_wheel && cmake .. -DXQC_ENABLE_WEBTRANSPORT=ON -DSSL_TYPE=babassl -DSSL_PATH={project}/third_party/babassl -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON && make -j$(nproc)",
]

before-build = [
    # 将 xquic 动态库复制到 Python 包目录内
    "cp {project}/build_wheel/libxquic.so {project}/python/pyxquic_wt/ || cp {project}/build_wheel/libxquic.dylib {project}/python/pyxquic_wt/ || true",
]

[tool.cibuildwheel.linux]
manylinux-x86_64-image = "manylinux2014"
manylinux-aarch64-image = "manylinux2014"
# auditwheel 自动将 libxquic.so + libssl.so + libcrypto.so 打包进 wheel
repair-wheel-command = "auditwheel repair -w {dest_dir} {wheel}"

[tool.cibuildwheel.macos]
# delocate 自动处理 dylib 依赖
repair-wheel-command = "delocate-wheel --require-archs {delocate_archs} -w {dest_dir} {wheel}"

[tool.cibuildwheel.windows]
before-all = [
    "cd {project} && cmake -B build_wheel -DXQC_ENABLE_WEBTRANSPORT=ON -DSSL_TYPE=boringssl -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON",
    "cmake --build {project}/build_wheel --config Release",
]
```

##### GitHub Actions CI

```yaml
# .github/workflows/build-wheels.yml
name: Build & Publish Wheels

on:
  push:
    tags: ["v*"]
  workflow_dispatch:  # 允许手动触发

jobs:
  build_wheels:
    name: Build wheels on ${{ matrix.os }}
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-22.04, macos-13, macos-14, windows-2022]
        # macos-13 = Intel, macos-14 = Apple Silicon

    steps:
      - uses: actions/checkout@v4
        with:
          submodules: recursive

      - name: Build wheels
        uses: pypa/cibuildwheel@v2.21
        with:
          package-dir: python/
        env:
          CIBW_BUILD: "cp38-* cp39-* cp310-* cp311-* cp312-* cp313-*"
          CIBW_SKIP: "*-win32 *-musllinux*"

      - uses: actions/upload-artifact@v4
        with:
          name: wheels-${{ matrix.os }}
          path: wheelhouse/*.whl

  # 仅在打 tag 时发布到 PyPI
  publish:
    needs: build_wheels
    runs-on: ubuntu-latest
    if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/')
    steps:
      - uses: actions/download-artifact@v4
        with:
          pattern: wheels-*
          merge-multiple: true
          path: dist/

      - uses: pypa/gh-action-pypi-publish@release/v1
        with:
          password: ${{ secrets.PYPI_API_TOKEN }}
```

#### 6.4 Wheel 内部结构（构建产物）

最终的 wheel 文件解压后包含：

```
pyxquic_wt/
├── __init__.py
├── client.py
├── server.py
├── session.py
├── stream.py
├── datagram.py
├── _event_loop.py
├── _ffi.py
├── _ffi_build.py
├── _pyxquic_wt_cffi.cpython-312-x86_64-linux-gnu.so   # CFFI 扩展
├── .dylibs/ (macOS) 或 .libs/ (Linux)
│   ├── libxquic.so.0.1.0       # xquic 动态库
│   ├── libssl.so.1.1            # SSL 库（自动打包）
│   └── libcrypto.so.1.1         # Crypto 库（自动打包）
```

**关键机制**：
- **auditwheel**（Linux）会扫描 `.so` 的依赖链，将 libxquic、libssl、libcrypto **复制进 wheel 包的 `.libs/` 目录**，并修改 RPATH
- **delocate**（macOS）做类似处理，修改 `@rpath`
- **delvewheel**（Windows）处理 DLL 依赖
- 结果：用户系统上**不需要预装任何 C 依赖**

#### 6.5 分阶段交付路径

| 阶段 | 安装方式 | 用户体验 | 优先级 |
|------|---------|---------|--------|
| A | 源码安装 | 需要 cmake + SSL 库 + `pip install ./python/` | 最先 |
| B | 本地 wheel | `cibuildwheel` 本地构建 `.whl` 文件 | 中间 |
| C | PyPI 发布 | `pip install pyxquic-wt` 一键安装 | 最终目标 |

阶段 A 的用户体验：
```bash
# 编译 xquic
cmake -B build -DXQC_ENABLE_WEBTRANSPORT=ON \
    -DSSL_TYPE=babassl -DSSL_PATH=./third_party/babassl \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON
make -C build -j

# 安装 Python 包
XQUIC_LIB_PATH=./build pip install ./python/
```

阶段 C 的用户体验：
```bash
pip install pyxquic-wt
```

---

### 第五阶段：自动化测试套件（~2天）

#### 7.1 测试矩阵

| 测试组合 | Client | Server | 测试内容 | 验证目标 |
|---------|--------|--------|---------|---------|
| C-C | xquic C client | xquic wt_test_server | bidi/uni/dgram echo | C 库基础功能 |
| Py-C | Python client | xquic wt_test_server | bidi/uni/dgram echo | Python→C 绑定 |
| Py-Py | Python client | Python server | bidi/uni/dgram echo | 纯 Python 端到端 |
| Chrome-C | Chrome browser | xquic wt_test_server | bidi/uni echo | 浏览器互通 |
| Py-aioquic | Python client | aioquic WT server | bidi/uni echo | 第三方互通 |
| aioquic-C | aioquic client | xquic wt_test_server | bidi/uni echo | 第三方互通 |
| Py-moq | Python client | moq-dev/moq relay | WT session 建立 | MoQ 生态互通 |

#### 7.2 CI 集成

```yaml
# tests job in GitHub Actions
test:
  needs: build_wheels
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Install wheel
      run: pip install wheelhouse/pyxquic_wt-*.whl
    - name: Run unit tests
      run: pytest python/tests/
    - name: Run interop tests
      run: |
        pip install aioquic
        python python/tests/test_interop.py
```

---

## 4. 关键文件清单

### 需要恢复（从 commit a36cfdbe）

```
src/webtransport/xqc_webtransport_ctx.c/h      # WT 引擎上下文
src/webtransport/xqc_webtransport_conn.c/h      # WT 连接管理
src/webtransport/xqc_webtransport_session.c/h   # WT Session
src/webtransport/xqc_webtransport_stream.c/h    # WT Bidi/Uni 流
src/webtransport/xqc_webtransport_dgram.c/h     # WT Datagram
src/webtransport/xqc_webtransport_request.c/h   # HTTP 请求解析
src/webtransport/xqc_webtransport_wire.c/h      # 变长整数编解码
src/webtransport/xqc_webtransport_defs.c/h      # 常量定义
include/xquic/xqc_webtransport.h                # 公共 API 头文件
demo/xqc_webtransport.h                         # Demo 用头文件
src/webtransport/wt_demo_server.c               # Echo 服务器
```

### 需要修改

```
CMakeLists.txt                          # 添加 XQC_ENABLE_WEBTRANSPORT 选项
src/http3/xqc_h3_defs.h                # 添加 WT SETTINGS ID 枚举
include/xquic/xqc_http3.h              # 添加 conn_settings 字段
src/http3/frame/xqc_h3_frame.c         # SETTINGS 写入
src/http3/xqc_h3_conn.c                # SETTINGS 接收
src/webtransport/xqc_webtransport_ctx.c # 使用 H3 层 SETTINGS
include/xquic/xqc_webtransport.h       # 补充缺失的 API
```

### 需要新建

```
python/pyxquic_wt/*.py                  # Python 封装包
python/pyproject.toml                   # 包元数据
python/setup.py                         # CFFI 编译集成
python/tests/*.py                       # 测试
python/examples/*.py                    # 示例
.github/workflows/build-wheels.yml      # CI 配置
```

---

## 5. 预估工作量

| 阶段 | 工作量 | 描述 |
|------|--------|------|
| 第一阶段 | ~3天 | 恢复 WT 代码 + H3 SETTINGS 集成 + CMake |
| 第二阶段 | ~2天 | RFC 合规修复 + Chrome/aioquic 互通验证 |
| 第三阶段 | ~5天 | Python CFFI 封装 + asyncio 事件循环桥接 |
| 第四阶段 | ~3天 | 预编译 Wheel 构建 + CI/CD 配置 |
| 第五阶段 | ~2天 | 自动化互通测试套件 + 文档 |
| **总计** | **~15 人天** | |

---

## 6. 风险与应对

| 风险 | 影响 | 应对措施 |
|------|------|---------|
| SSL 库打包 | wheel 体积增大；不同平台 SSL 差异 | auditwheel/delocate 自动处理；考虑静态链接 |
| Windows 支持 | BabaSSL 在 Windows 的编译适配 | 优先 Linux/macOS；Windows 使用 BoringSSL |
| CFFI 回调生命周期 | xquic 回调密集，Python GC 可能回收 callback | 在 Python 对象中持有 callback 引用 |
| WebTransport 标准演进 | RFC 9220 vs draft-02/07 细微差异 | 逐项对照 RFC 9220 检查并修复 |
| CI 资源 | 跨平台构建需要多个 runner | 使用 GitHub Actions 免费额度 |
| xquic 主线 API 变更 | 基于 origin/main 开发，但 main 持续演进 | 定期 rebase；CI 自动检测 |
