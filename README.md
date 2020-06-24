# pegasocks (WIP)

是一个基于 socks5 协议的代理客户端，意图在于支持多种类型的代理服务。
C 语言编写，轻量，支持类 unix 系统。

## 依赖

- openssl 1.1.1
- libevent2
- json-c

## 编译

> mkdir build && cd build
>
> cmake .. && make

## 运行

> pegas -c config.json

## 配置文件

下面给出一个例子

```json
{
  "servers": [
    {
      "server_address": "yourhost.name",
      "server_type": "trojan",
      "server_port": 443,
      "password": "password",
      "websocket": {
        "path": "/trojan",
        "hostname": "yourhost.name"
      }
    }
  ],
  "local_address": "0.0.0.0",
  "local_port": 1080,
  "timeout": 60,
  "log_level": 1,
  "log_file": "app.log"
}
```

从最外层开始解释

- `local\_address` 必填，本地服务(socks5)监听地址
- `local\_port` 必填，本地服务(socks5)监听端口
- `log\_level` 可选，为 0 到 3，等级依次是：debug、info、warn 和 error，默认为 1
- `log\_file` 可选，日志输出位置，不填时，写到 stderr

### Servers 字段

是一个数组，每个成员的字段如下

- `server\_address` 必填，服务器地址
- `server\_port` 必填，服务器端口
- `server\_type` 必填，服务器类型，目前仅支持一种 `trojan`
- `password` 必填，密码

当 `server\_type` 为 `trojan` 时，支持

- `websocket` 可选，内容为对象，不存在时，走直连(trojan-gfw)，填写后可以走 websocket(wss) 并利用 CDN 转发(trojan-go)
  - `path` websocket 的路径

trojan 的传输层由 ssl/tls 保护，因此 `server\_port` 为 443，同时，服务器还需要绑定域名并申请 https 证书。

## 开发计划

- 多种协议支持
  - [x] trojan (wss)
  - [ ] trojan (直连)
  - [ ] v2ray (wss)
- 多类型服务端负载均衡
- 平台适配
  - [ ] osx 适配（应该可以直接用，暂未测试）
  - [ ] windows 适配

