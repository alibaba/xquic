# Case Test Trouble Shooting

本文记录 case_test 路由和并行化重构中已经暴露过的坑点。它不是新增
case 的教程；新增流程见 `case_test/README.md`。这里重点回答：
失败时先看什么、如何区分脚本问题和环境问题、哪些现象不能直接当成
测试结果。

## 快速定位

先确认当前构建目录、执行计划、case 归属和架构检查：

```bash
bash scripts/case_test.sh --execution-plan
bash scripts/case_test.sh --inventory
case_test/lib/architecture_check.rb "$(pwd)" --all
```

并行执行失败后，先从 runner 输出里的 `run-id` 找到本轮目录：

```bash
find build/validation/case_test_parallel/<run-id> \
    -name case_test.failures -size +0 -print
```

每个 shard 的权威证据在本轮目录下：

- `case_test.log`: 该 shard 的原始输出。
- `case_test.events`: runner 解析到的结构化 case 事件。
- `case_test.results`: 归一化后的 `pass:1` / `pass:0` 结果。
- `case_test.failures`: 失败 case 的结果行。
- `case-logs/<case>/`: 单个 case 复制出来的 `stdlog`、`clog`、`slog`
  等细节日志。

终端上的并行输出只适合看进度，不适合作为最终判断。

## 常见坑点

### 并行 stdout 会交错

多个 shard 同时输出时，终端日志会把不同 case 的 `[ RUN ]`、`pass:0`
和普通文本混在一起。不要用终端顺序推断哪个 case 失败，也不要只看
最后几行判断整体结果。以每个 shard 的 `case_test.events`、
`case_test.results` 和 `case_test.failures` 为准。

### 旧目录或旧日志会污染判断

历史版本把日志写到 `case_test_parallel/<group>`。新结构必须写到
`case_test_parallel/<run-id>/<group>`。如果诊断时看到没有 `run-id`
的路径，先确认是不是旧日志，不要把旧失败当成本轮失败。

### 失败不能只靠 grep stdout

原始 case 输出里可能有 `grep: empty (sub)expression`、裸 `pass:0`、
或者 helper 中间输出。runner 必须以每个 `case_test_case` 的退出状态
生成 event，再由 event 汇总结果。若 `run` 数量和 `expected` 数量不等，
优先查注册、selector 或 event 写入逻辑，而不是先查协议行为。

### BSD 工具差异会破坏计数

macOS 上 `wc -l` 可能带前导空格，`grep` 在无匹配时返回 1，配合
`set -euo pipefail` 会让计数逻辑提前退出。脚本里做统计时优先使用
`awk`，或对允许无匹配的 `grep` 明确处理返回值。

### 命令替换可能卡住后台进程

如果用 `output=$(case_function)` 包裹整个 case，case 内启动的后台
server 可能继承 stdout/stderr，导致命令替换一直等文件描述符关闭。
case runner 应把每个 case 的输出重定向到独立文件，再在 case 结束后
回放需要展示的内容。

### case 必须唯一归属

每个端到端 case 只能在一个 group 中注册一次。功能相关但不负责执行的
关系不要复制 case；可以写到文档或后续的 related metadata。新增或移动
case 后先跑：

```bash
bash scripts/case_test.sh --inventory
case_test/lib/architecture_check.rb "$(pwd)" --all
```

### group 脚本不要混入遗留尾部逻辑

native group 脚本应该只声明 group、定义函数、注册 `case_test_case`、
再交给公共 runner 执行。迁移时残留的旧入口、临时文本或重复 helper
会造成重复执行、`command not found` 或发现阶段误判。架构检查需要覆盖
这些异常入口。

### feature-gated group 由构建配置决定

不要用 `LOCAL_TEST` 额外区分 FEC 这类功能 case。是否执行应由
`manifest.yml` 中的 `requires_cmake` 和当前 `XQC_BUILD_DIR/CMakeCache.txt`
共同决定。默认构建应跳过 `transport.fec`；FEC-enabled 构建才应把它计入
expected case 数。

### sandbox 失败不等于 case 失败

在受限环境中运行 UDP/socket 用例时，可能出现 `Operation not permitted`、
`addr or cid not avail`、`bind socket failed errno:1` 等错误。这类现象
优先按环境问题处理：用同一条非 sudo 命令在普通终端复现。不要把 sandbox
中的权限错误直接归因到并行逻辑或协议代码。

### sudo 依赖要在调度前暴露

包含 sudo 网络配置的 shard 需要用户在同一个 shell 中先执行 `sudo -v`。
runner 应在启动 shard 前检查凭据；缺少凭据时应作为环境失败退出，而不是
调度一半后产生混杂的 case 失败。agent 不应自行尝试 sudo。

### 资源隔离优先级

并行执行的隔离顺序是：

1. 每轮 `run-id` 目录。
2. 每个 shard 的独立 workdir。
3. manifest 固定 `port_offset`。
4. per-shard 文件名、token、session ticket、transport parameter。
5. PID 清理和端口清理。

证书这类只读共享文件可以统一使用，不需要加锁。会写入或被覆盖的资源
必须放进 shard workdir，或用 shard 名称生成独立路径。

### timeout 要落到 case 结果

`CASE_TEST_SHARD_TIMEOUT` 用来限制整个 shard；`CASE_TEST_CASE_TIMEOUT`
用来限制单个 case。单 case 超时后应写入 event 并标记该 case 失败，
避免整个 shard 卡到全局超时后没有明确失败 case。

### validate 和 CI 应使用同一语义

本地完整验证和 CI 不应走两套不同入口。`scripts/validate.sh full`、
GitHub workflow 和人工本地命令应最终调用同一个 native runner：

```bash
bash scripts/case_test.sh --execute --parallel --jobs auto --require-complete
```

如果 CI 额外逐个 group 串行调用，就会失去并行提速，也会让本地复现和
线上行为不一致。

## 判断失败类型

### 覆盖数量不一致

症状：runner 汇总的 `run` 不等于 `expected`。

优先检查：

- `case_test_case` 是否遗漏或重复。
- selector 是否把 build-gated group 错误纳入或排除。
- event 文件是否在 case 失败、timeout、被信号终止时仍然写入。
- `--require-complete` 是否正确把缺失 case 变成失败。

### 大量 case 在 1 秒内失败

症状：多个 case 立即 `pass:0`，日志包含 bind、socket、route、permission
相关错误。

优先检查：

- 是否在 Codex sandbox 或受限 shell 中运行。
- 需要 sudo 的 shard 是否已经 `sudo -v`。
- 端口是否被旧进程占用。
- shard workdir 是否复用了旧的可写文件。

### 单个 case 稳定失败

优先查看：

```bash
tail -n 160 build/validation/case_test_parallel/<run-id>/<group>/case_test.log
find build/validation/case_test_parallel/<run-id>/<group>/case-logs/<case> \
    -maxdepth 2 -type f
```

这类失败通常才进入协议行为、case 参数、server/client 配置或日志断言的
排查。

### 并行慢但没有失败

理论耗时接近最慢 shard 的耗时，再加上构建、准备、排队、日志上传和
调度开销。如果 CI 用统一脚本内部并行，耗时应该接近最长 group；如果
workflow 逐个 group 串行调用，耗时会接近所有 group 之和。

排查时确认：

- runner 输出里是否只有一次统一调度。
- `jobs` 是否来自 `--jobs auto` 和 manifest 的 `max_parallel_jobs`。
- 是否有 shard 因 sudo、timeout、端口冲突或等待后台进程而拖住整体。
- CI 是否还有额外的串行 case_test 步骤。

## 当前重构保留的验收点

- 默认构建不应执行 FEC build-gated group。
- FEC-enabled 构建应把 `transport.fec` 纳入 expected case 数。
- 每个 case 有且仅有一个 native group 归属。
- 并行执行由 `scripts/case_test.sh` 统一调度，不依赖 GitHub matrix
  shard 才能并行。
- 本地和 CI 的完整 case_test 入口语义一致。
- 失败判断基于 event/result 文件和 expected count，不基于交错 stdout。
- 验证日志属于本地临时产物，不应提交。
