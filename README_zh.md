<img src="./logo/icon.svg" width="150" align="left" />

# pegasocks [![Cirrus CI Build Status](https://api.cirrus-ci.com/github/chux0519/pegasocks.svg)](https://cirrus-ci.com/github/chux0519/pegasocks)

是一个基于 socks5 协议的代理客户端，意图在于支持多种类型的代理服务。
C 语言编写，轻量，支持类 unix 系统(Linux/WSL/BSDs/OSX)。

⚠️ 这是一个正在开发中的项目，请自行考虑使用成本和风险。

中文 | [English](./README.md)

## 特点

与其他大多数支持多协议的客户端不同，pegasocks 不依赖各种第三方 core(比如 v2ray-core 等)，而是真的去实现相关协议的拆装，并且尽可能的照顾性能。因此它

1. 🍃 足够轻量，没有 QT 或是 boost 或是其他第三方二进制的依赖。
2. 🚀 性能优先，默认多个 worker 线程，因此理论上吞吐量会比较高（待benchmark）
3. 🚥 这是一个 learn by doing 项目，欢迎大家 review 代码，提供优化思路和 C 语言编程相关的指导。
4. ❌ 没有 GUI，可以直接配合 systemd, launchd, rc 或是各种自定义脚本配置开机启动。后期计划开发一个简单的 tray indicator，在系统的托盘里显示，并且提供一些简单的交互，总之重型的 GUI 是不在考虑范围内的。

## 依赖

- openssl 1.1.1 / mbedtls 2.27.0
- libevent2
- pcre (lagacy) 可选的，开启 ACL 支持时会需要它

其他依赖通过 git submodule 来进行管理，因此需要在获取代码后

> git submodule update --init

或者在 clone 代码时添加 `--recursive` 参数

## 安装

如果你使用 Arch Linux，可以使用 aur 进行安装

> yay -S pegasocks-git --overwrite /usr/local/bin/pegas,/usr/local/share/pegasocks/*

或者直接编译如下

## 编译

使用 cmake

> mkdir build && cd build
>
> cmake -DCMAKE_BUILD_TYPE=Release -DWITH_ACL=ON -DUSE_JEMALLOC=ON .. && make

### 可选的 option 有

|选项|含义|默认值|
| --- | --- | --- |
|-DUSE_MBEDTLS|是否使用 mbedtls 代替 openssl | OFF|
|-DUSE_JEMALLOC|是否使用 jemalloc | OFF|
|-DUSE_STATIC|是否采用 static link | OFF |
|-DWITH_ACL|是否打开 ACL 支持 (这会增加 libcork/ipset/pcre 的依赖，因此会增加程序最终的大小)| OFF |
|-DWITH_APPLET|是否开启系统托盘支持 (这会依赖平台相关的一些系统库，因此会增加程序最终的大小)| OFF |

另外可以通过以下参数自定义 JeMalloc/Libevent2/MbedTLS/OpenSSLx/PCRE 的寻找根目录

> -DOpenSSLx_ROOT=/xxxxxx/xxx/xxx 指定 openssl root
> 
> -DLibevent2_ROOT=xxxxxx  指定 libevent root
> 
> 以此类推

## 运行

> pegas -c config.json -t 4

- `-c` 指定配置文件，默认会依次尝试 `$XDG_CONFIG_HOME/.pegasrc` 或者 `$XDG_CONFIG_HOME/pegas/config` 
- `-t` 指定工作线程数量，默认为 4

## 配置

见[配置文档](https://github.com/chux0519/pegasocks/wiki/%E9%85%8D%E7%BD%AE%E8%AF%B4%E6%98%8E)


## 交互

通过指定配置文件的 "control_port" 或是 "control_file" 字段，开启 TCP 端口或者 unix socket 和程序进行交互，配合 netcat / socat 与相关的端口或是文件进行交互，支持以下两个命令

- `GET SERVERS`，返回服务器的信息
- `SET SERVER $idx`，设置当前服务器

在 linux 下 socat 演示

<img src="https://i.imgur.com/dlFuKtg.png" width="512" />

开启系统托盘时，直接使用托盘进行交互，见下

## 系统托盘

默认编译二进制文件不带 GUI，带上参数 `-DWITH_APPLET=ON` 开启系统托盘功能。

> cmake -DCMAKE_BUILD_TYPE=Release -DWITH_APPLET=ON .. && make

### Linux 

<img src="https://i.imgur.com/Ny0WMJA.png" width="512" />

从命令行启动时，将 `logo/icon.svg` 放到 pegas 同级目录，然后正常使用即可。


### OSX

<img src="https://i.imgur.com/jOA04aU.png" width="512" />

OSX上，默认会将二进制打包成 app bundle，直接将打包出的 `build/PegasApp.app` 复制到应用程序即可。

⚠️注:如果遇到无法启动的状况，请确认

1. 系统安装了 libevent (brew install libevent)
2. 是否有 **配置文件**，app bundle 会检测 `~/.config/.pegasrc` 或者 `~/.config/pegas/config`
