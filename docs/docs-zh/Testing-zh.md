# Testing  XQUIC

本文档主要描述了如何使用 test_client 和 test_server 进行测试。

## 运行步骤

在运行 test_server 之前，需要先生成证书：

```bash
cd build
keyfile=server.key
certfile=server.crt
openssl req -newkey rsa:2048 -x509 -nodes -keyout "$keyfile" -new -out "$certfile" -subj /CN=test.xquic.com
```

运行 test_client 和 test_server：

```bash
./test_server -l d > /dev/null &
./test_client -a 127.0.0.1 -p 8443 -s 1024000 -E
```

## 参数含义

以下参数都可以在 tests/test_client.c 和 tests/test_server.c 的 `usage()` 中找到对应说明，如本文档有更新滞后的情况，请以最新代码为准。

### test_client

| Option | Usage |
| :----: | ----  |
|   -a   | Server addr. |
|   -p   | Server port. |
|   -P   | Number of Parallel requests per single connection. Default 1. |
|   -n   | Total number of requests to send. Defaults 1. |
|   -c   | Congestion Control Algorithm. r:reno b:bbr c:cubic B:bbr2 bbr+ bbr2+ |
|   -C   | Pacing on. |
|   -t   | Connection timeout. Default 3 seconds. |
|   -T   | Transport layer. No HTTP3. |
|   -1   | Force 1RTT. |
|   -s   | Body size to send. |
|   -w   | Write received body to file. |
|   -r   | Read sending body from file. priority s > r |
|   -l   | Log level. e:error d:debug. |
|   -E   | Echo check on. Compare sent data with received data. |
|   -d   | Drop rate ‰. |
|   -u   | Url. default https://test.xquic.com/path/resource |
|   -H   | Header. eg. key:value |
|   -h   | Host & sni. eg. test.xquic.com |
|   -G   | GET on. Default is POST |
|   -x   | Test case ID |
|   -N   | No encryption |
|   -6   | IPv6 |
|   -V   | Force cert verification. 0: don't allow self-signed cert. 1: allow self-signed cert. |
|   -q   | name-value pair num of request header, default and larger than 6 |
|   -o   | Output log file path, default ./clog |

### test_server

| Option | Usage |
| :----: | ----  |
|   -p   | Server port. |
|   -e   | Echo. Send received body. |
|   -c   | Congestion Control Algorithm. r:reno b:bbr c:cubic B:bbr2 bbr+ bbr2+ |
|   -C   | Pacing on. |
|   -s   | Body size to send. |
|   -w   | Write received body to file. |
|   -r   | Read sending body from file. priority e > s > r |
|   -l   | Log level. e:error d:debug. |
|   -u   | Url. default https://test.xquic.com/path/resource |
|   -x   | Test case ID |
|   -6   | IPv6 |
|   -b   | batch |
|   -S   | server sid |
|   -o   | Output log file path, default ./slog |
