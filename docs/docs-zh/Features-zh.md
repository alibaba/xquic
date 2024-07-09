# Features
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


