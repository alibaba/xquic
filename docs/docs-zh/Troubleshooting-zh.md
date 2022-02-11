# Trouble Shooting Guide

> iOS 编译失败

类似 [Discussions #21](https://github.com/alibaba/xquic/discussions/21) 的问题，最新版本已经fix，请拉取最新代码。

> MacOS 编译失败

先检查是否添加了 `-DPLATFORM=mac` 参数。 

> 首次运行 test_server 后，报错：error create engine

需要先生成证书，见 [Testing](./Testing-zh.md)。

> 运行 test_client 时，更改 host of url 后报错，例如：[#67](https://github.com/alibaba/xquic/issues/67)
> 
> ./test_client -u "https://aaa.test/1M" -G -a 127.0.0.1 -p 443 (success)
> 
> ./test_client -u "https://bbb.test/1M" -G -a 127.0.0.1 -p 443 (failed)

测试程序没有按照域名来保存文件，需要手动删除session ticket、传输参数、token

```
cd build
rm -f test_session tp_localhost xqc_token
```