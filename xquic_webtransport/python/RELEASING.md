# pyxquic-wt 发布指南

## 前置条件

- Python >= 3.9
- Git submodules 已初始化：`git submodule update --init --recursive`
- C 编译器 + cmake

## 本地开发

```bash
# 一键编译（默认 BabaSSL）
bash scripts/build_wt_py.sh

# 用 BoringSSL（公网 CI 使用此模式）
SSL_BACKEND=boringssl bash scripts/build_wt_py.sh

# 可编辑安装
cd xquic_webtransport/python
pip install -e .

# 验证
python -c "from pyxquic_wt import connect, serve; print('OK')"

# 生成测试证书
pyxquic-wt gen-cert --outdir ../../certs

# 运行测试
python -m pytest tests/test_wire.py tests/test_e2e_lowlevel.py tests/test_echo.py tests/test_stream_unit.py -v
```

## 发布到 PyPI

### 1. 更新版本号

编辑 `pyxquic_wt/__init__.py`：

```python
__version__ = "0.2.0"  # 改为新版本
```

### 2. 打 tag 并推送

```bash
git add -A
git commit -m "release: v0.2.0"
git tag v0.2.0
git push origin feat/webtransport --tags
```

### 3. 自动构建

推送 tag 后 GitHub Actions 自动触发 `.github/workflows/build-wheels.yml`：

- **构建平台**：ubuntu-latest (x86_64), macos-13 (x86_64), macos-latest (arm64)
- **Python 版本**：3.9, 3.10, 3.11, 3.12, 3.13
- **SSL 后端**：BoringSSL（公网可用，无需内部仓库）
- **产物**：manylinux2014 wheel + macOS wheel + sdist

### 4. 自动发布

当 tag 匹配 `v*` 时，`publish` job 自动将 wheel 发布到 PyPI。

需要配置 GitHub 仓库的 PyPI trusted publisher：
1. 在 [pypi.org](https://pypi.org) 注册项目
2. Settings → Publishing → Add trusted publisher
3. 填入 GitHub owner/repo + workflow 文件名 `build-wheels.yml`

### 5. 手动发布（备用）

```bash
# 构建
cd xquic_webtransport/python
SSL_BACKEND=boringssl bash ../../scripts/build_wt_py.sh
pip install build twine
python -m build

# 上传
twine upload dist/*
```

## CI 结构

| Workflow | 触发条件 | 作用 |
|----------|---------|------|
| `pyxquic-wt.yml` | push/PR 到 main, feat/webtransport | 跑测试（BabaSSL + BoringSSL × Python 3.9-3.12 × ubuntu/macOS） |
| `build-wheels.yml` | tag `v*` 或手动 dispatch | cibuildwheel 构建 wheel + 发布 PyPI |

## SSL 后端说明

| 后端 | 场景 | 说明 |
|------|------|------|
| BabaSSL | 内部开发 | 阿里内部仓库，公网不可用 |
| BoringSSL | CI / PyPI wheel | 公网可用，cibuildwheel 默认使用 |

`build_wt_py.sh` 通过 `SSL_BACKEND` 环境变量切换：

```bash
SSL_BACKEND=boringssl bash scripts/build_wt_py.sh
```

## 用户安装

发布后用户只需：

```bash
pip install pyxquic-wt
```

可选证书工具：

```bash
pip install 'pyxquic-wt[cert]'
pyxquic-wt gen-cert
```
