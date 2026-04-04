# Testing XQUIC

This document describes how to test with test_client and test_server.

## Steps

Before running test_server, generate certificates:

```bash
cd build
keyfile=server.key
certfile=server.crt
openssl req -newkey rsa:2048 -x509 -nodes -keyout "$keyfile" -new -out "$certfile" -subj /CN=test.xquic.com
```

Run test_client and test_server:

```bash
./tests/test_server -l d > /dev/null &
./tests/test_client -a 127.0.0.1 -p 8443 -s 1024000 -E
```

Note: session tickets, transport parameters, and tokens may be incompatible across different servers. If you connect test_client to one server and then to another, remove the locally saved test_session, tp_localhost, and xqc_token files; otherwise the connection can fail.
Also, different domains on the same server may use different certificates. If you connect to the same server with different domains, the locally saved test_session file can also cause connection failures.

## Options

These options are documented in the `usage()` output in tests/test_client.c and tests/test_server.c. If this document falls behind, use the latest code as the source of truth.

### test_client

| Option | Usage |
| :----: | ----  |
|   -a   | Server addr. |
|   -p   | Server port. |
|   -P   | Number of Parallel requests per single connection. Default 1. |
|   -n   | Total number of requests to send. Defaults 1. |
|   -c   | Congestion Control Algorithm. r:reno b:bbr c:cubic B:bbr2 bbr+ bbr2+ P:copa |
|   -C   | Pacing on. |
|   -t   | Connection timeout. Default 3 seconds. |
|   -T   | Transport layer. No HTTP3. |
|   -1   | Force 1RTT. |
|   -s   | Body size to send. |
|   -F   | Abs_timeout to close conn. >=0. |
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
|   -M   | Enable multi-path on. |
|   -i   | Multi-path interface. e.g. -i interface1 -i interface2. |
|   -R   | Enable reinjection. Default is 0, no reinjection |
|   -V   | Force cert verification. 0: don't allow self-signed cert. 1: allow self-signed cert. |
|   -q   | name-value pair num of request header, default and larger than 6 |
|   -o   | Output log file path, default ./clog |
|   -f   | Debug endless loop. |
|   -e   | Epoch, default is 0. |
|   -D   | Process num. default is 2. |
|   -b   | Create connection per second. default is 100. |
|   -B   | Max connection num. default is 1000. |
|   -J   | Random CID. default is 0. |
|   -Q   | Multipath backup path standby, set backup_mode on(1). default backup_mode is 0(off). |
|   -A   | Multipath request accelerate on. default is 0(off). |

### test_server

| Option | Usage |
| :----: | ----  |
|   -a   | Server addr. |
|   -p   | Server port. |
|   -e   | Echo. Send received body. |
|   -c   | Congestion Control Algorithm. r:reno b:bbr c:cubic B:bbr2 bbr+ bbr2+ P:copa |
|   -C   | Pacing on. |
|   -L   | Endless_sending on. default is off. |
|   -s   | Body size to send. |
|   -w   | Write received body to file. |
|   -r   | Read sending body from file. priority e > s > r |
|   -l   | Log level. e:error d:debug. |
|   -u   | Url. default https://test.xquic.com/path/resource |
|   -x   | Test case ID |
|   -6   | IPv6 |
|   -b   | batch |
|   -S   | server sid |
|   -M   | Enable multi-path on. |
|   -R   | Enable reinjection. Default is 0, no reinjection |
|   -E   | load balance id encryption on |
|   -K   | load balance id encryption key |
|   -o   | Output log file path, default ./slog |
|   -m   | Set mpshell on |
|   -Q   | Multipath backup path standby, set backup_mode on(1). default backup_mode is 0(off). |
