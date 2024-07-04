# Features
## qlog
Based on qlog ([draft-ietf-quic-qlog-main-schema](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-main-schema/), [draft-ietf-quic-qlog-quic-events](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-quic-events/) and [draft-ietf-quic-qlog-h3-events](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-h3-events/))，xquic implements quic event logging.

### Activate qlog by DXQC_ENABLE_EVENT_LOG
```shell
cd build
rm -rf * 
# add "-DXQC_ENABLE_EVENT_LOG=1"
cmake -DGCOV=on -DCMAKE_BUILD_TYPE=Debug -DXQC_ENABLE_TESTING=1 -DXQC_SUPPORT_SENDMMSG_BUILD=1 -DXQC_ENABLE_EVENT_LOG=1 -DXQC_ENABLE_BBR2=1 -DXQC_ENABLE_RENO=1 -DSSL_TYPE=${SSL_TYPE_STR} -DSSL_PATH=${SSL_PATH_STR} ..

make -j
```
### Example
Qlog defines three event importance levels, in decreasing order of importance and expected usage: core, base, extra. The level can be set by "--qlog_importance" argument：
```shell
./tests/test_server -l e -e --qlog_importance extra

./tests/test_client -s 10240 -l e -t 1 -E --qlog_importance extra
```

To disable qlog, using "--qlog_disable":
```shell
./tests/test_server -l e -e --qlog_disable

./tests/test_client -s 10240 -l e -t 1 -E --qlog_disable
```

### JSON format serialization
```shell
python ../scripts/qlog_parser.py --clog clog --slog slog --qlog_path demo_qlog.json
```


