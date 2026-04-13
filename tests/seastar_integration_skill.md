# Seastar XQUIC 集成 Skill

这个目录下的 Seastar 集成样例遵循以下约束：

1. **server 优先**
   - 当前只落地 `/home/runner/work/xquic/xquic/tests/xquic_server_seastar.cpp`
   - 目标是先把服务端收包、驱动 `xqc_engine_main_logic()`、以及发送路径闭环跑通

2. **queue 继续上提为 integration 层**
   - XQUIC 的 `write_socket` 回调是同步接口
   - Seastar UDP 发送是异步 future 接口
   - 当前样例把 `/home/runner/work/xquic/xquic/tests/xquic_seastar_queue.hh` 作为底层队列细节，进一步通过 `/home/runner/work/xquic/xquic/tests/xquic_seastar_integration.hh` 暴露更通用的 integration 层 enqueue/flush 接口

3. **tests/ 内实验性集成**
   - Seastar 代码只放在 `/home/runner/work/xquic/xquic/tests/`
   - 不侵入核心库实现
   - 默认构建关闭，仅在显式开启时编译

4. **依赖策略**
   - 允许后续在 `tests/` 范围内引入 `boost::lockfree::spsc_queue`
   - 当前实现没有新增该依赖，而是先用最小 `std::deque` 队列完成闭环，降低构建复杂度

5. **推荐迭代顺序**
   - server
   - queue
   - integration
   - client

## 构建方式

Seastar 样例默认关闭，需要显式开启：

```bash
cmake -S /home/runner/work/xquic/xquic -B /tmp/xquic-build \
  -DXQC_ENABLE_TESTING=ON \
  -DXQC_ENABLE_SEASTAR_EXAMPLE=ON \
  -DSSL_TYPE=boringssl \
  -DSSL_PATH=/path/to/boringssl \
  -DSSL_INC_PATH=/path/to/boringssl/include \
  -DSSL_LIB_PATH="/path/to/boringssl/build/libssl.a;/path/to/boringssl/build/libcrypto.a"
```

要求系统中可通过 `pkg-config` 找到 `seastar`。

## 当前样例能力

- Seastar UDP 收包
- 调用 `xqc_engine_packet_process()` / `xqc_engine_finish_recv()`
- 通过独立 integration 层接口异步 flush 出站 UDP 包
- transport 模式下演示 `user_conn` 归属、stream 生命周期、以及“收 frame 请求/组 frame 响应/回写消息”的基础应用层协议流程
- 最小 HTTP/3 文本响应

## transport demo frame 协议

transport 样例当前使用一个最小 frame 头：

- `type: 1 byte`
- `length: 4 bytes`（大端）
- `payload: length bytes`

当前约定的 frame type：

- `0x01` `HELLO`：可选，携带 demo client 标识或版本信息
- `0x02` `MESSAGE`：必选，携带业务请求文本；允许多帧拼接
- `0x03` `METADATA`：可选，携带额外扩展信息
- `0x80` `STATUS`：服务端响应状态
- `0x81` `RESULT`：服务端返回的处理结果摘要
- `0x82` `INFO`：服务端返回的连接/流上下文信息
- `0xff` `ERROR`：请求非法时的错误响应

这样可以让 transport demo 更接近正式协议的“typed frame”风格，同时不把样例耦合到某个具体业务模型里。

## 后续扩展建议

- 将 `std::deque` 替换为更严格的 SPSC 队列实现
- 补齐 client 样例
- 将 integration 层下沉为可复用的 server/client 共享桥接
