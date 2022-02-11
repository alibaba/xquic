# FAQ

> 支持的协议版本

* draft-29
* version 1

> 依赖项

因需要 TLS 1.3 功能依赖 SSL 库，下面两者可二选一（都支持），由编译选项控制：
* BoringSSL
* BabaSSL

如果需要跑 test client/test server 或者本地回归测试，需要安装：
* libevent
* CUnit

> 编译方法

见 [QuickStart](https://github.com/alibaba/xquic#quickstart-guide)

> XQUIC 还支持什么平台？其他平台如何编译？

XQUIC 支持 Android、iOS、Linux 和 MacOS，编译方法参见 [Platforms](../Platforms.md)。

> 在各平台的编译产物大小

* Android
  - 包含BoringSSL：v8a(64位) - 1.3MB，v7a(32位) - 947KB
  - 不包含BoringSSL：v8a(64位) - 363KB, v7a(32位) - 275KB
* iOS
  - 包含BoringSSL：arm64 - 1.13 MB, armv7 - 0.9MB
  - 不包含BoringSSL：arm64 - 325KB，armv7 - 289KB

> 为什么我编译出来包体积那么大？

需要使用各个平台的 toolchain 进行压缩
* Linux/MacOS 下可以通过运行 `strip libxquic.so` 命令进行压缩。
* Android 可以使用交叉编译工具链压缩，例如：
```
aarch64-linux-android-strip release/arm64-v8a/libxquic.so
arm-linux-androideabi-strip release/armeabi-v7a/libxquic.so
```
* iOS 可以使用 Xcode 环境里安装的 strip 工具，例如：
```
strip arm64/libxquic.a
```

> 基本功能支持情况

* 0-RTT
* 连接迁移（分支）
* ...

其他功能支持情况，参考互通性验证：https://interop.seemann.io/

> 当前尚未支持 xxx 功能（例如 multipath），未来是否有计划支持？

请先查询 [Milestones](https://github.com/alibaba/xquic/milestones) 中是否计划支持该功能，如果你想要的功能暂时不在我们的计划中，可以通过 Issue 提交 New Feature Request。

> QUIC-LB支持：负载分发与均衡

XQUIC是一个纯协议实现库，只包含协议栈能力，没有负载均衡功能。
QUIC-LB草案主要是规约CID生成算法。
XQUIC支持以cid generate callback形式由上层生成&设置CID；
上层未设置callback情况下，由XQUIC内部随机生成CID。

> 同一个 connection 的多个 stream 可以在多个线程中使用吗？

XQUIC 不支持同一个连接跑在不同的线程上。建议用同一个线程处理相同xquic connection的socket IO和stream/request读写，如果业务必须在不同线程上处理不同stream/request，可以采用其他方式进行线程间通信，比如共享进程内存、unix socket，IO线程收到stream/request数据后转发给业务线程。