<img src="./logo/icon.svg" width="150" align="left" />

# pegasocks [![Cirrus CI Build Status](https://api.cirrus-ci.com/github/chux0519/pegasocks.svg)](https://cirrus-ci.com/github/chux0519/pegasocks)

is a (socks5)proxy client written in C, intended to support multiple types of proxy protocols(trojan, v2ray, \*shadowsock, ..).
It is lightweight and supports unix-like systems(Linux/WSL/BSDs/OSX).

⚠️ This project is under development, please consider the cost and risk of use at your own discretion.

[中文](./README_zh.md) | English

## Features

Unlike most other clients that support multiple protocols, pegasocks does not rely on various third-party cores (e.g. v2ray-core, etc.), but really goes for the disassembly of the relevant protocols and takes care of performance as much as possible. Therefore it

1. 🍃 is light enough that there are no QT or boost or other third-party binary dependencies.
2. 🚀 Performance-first, with multiple worker threads by default, so theoretically higher throughput to be benchmarked)
3. 🚥 This is a learn by doing project, feel free to review the code, provide optimization ideas and C programming related guidance.
4. ❌ There is no GUI, you can directly work with systemd, launchd, rc or various custom scripts toconfigure the bootu.But you can optianly choose to build a simple tray indicator to interact with it, but in short, a heavy-duty GUI is not under consideration.

## Dependencies

- openssl 1.1.1 / mbedtls 2.27.0
- libevent2.12 (on OSX, need the [latest](https://github.com/libevent/libevent/tree/master) version)
- pcre (lagacy) optional，will need it when ACL is enabled

Other dependencies are managed through git submodule, so you need to run following command after git clone.

> git submodule update --init

Or add `--recursive` parameter in `git clone` command.

## Install

If you use Arch Linux, you can install the latest version via AUR

> yay -S pegasocks-git --overwrite /usr/local/bin/pegas,/usr/local/share/pegasocks/*

Or you can build it yourself as following

## Build

> mkdir build && cd build
>
> cmake -DCMAKE_BUILD_TYPE=Release -DWITH_ACL=ON -DUSE_JEMALLOC=ON .. && make

### Cmake Options

|option|meaning|default|
| --- | --- | --- |
|-DUSE_MBEDTLS|Whether to use mbedtls instead of openssl| OFF|
|-DUSE_JEMALLOC|Whether to use jemalloc| OFF|
|-DUSE_STATIC|Whether to use static links| OFF |
|-DWITH_ACL|Whether to open ACL support (this will use more dependencies( libcork/ipset/PCRE ), so it will increase the final size of the program)| OFF |
|-DWITH_APPLET|Whether to enable system tray support (this will depend on some system libraries and will therefore increase the final size of the program)| OFF |

You can also customize the search root of JeMalloc/Libevent2/MbedTLS/OpenSSLx/PCRE with the following parameters.

> -DOpenSSLx_ROOT=/xxxxxx/xxx/xxx for openssl root
> 
> -DLibevent2_ROOT=xxxxxx  for libevent root
> 
> and so on

## Run

> pegas -c config.json -t 4

- `-c` specifies the configuration file, by default it will try `$XDG_CONFIG_HOME/.pegasrc` or `$XDG_CONFIG_HOME/pegas/config` in order 
- `-t` specifies the number of worker threads, default is 4
- `-a` specifies the ACL file if pegas is build with ACL feature

## Configuration

see [man page](https://github.com/chux0519/pegasocks/wiki/manpage) or [wiki](https://github.com/chux0519/pegasocks/wiki/%E9%85%8D%E7%BD%AE%E8%AF%B4%E6%98%8E)


## Interaction

The "control_port" or "control_file" field of the configuration file can be used to open a TCP port or a unix socket to interact with the program. Use netcat / socat to interact with the relevant port or file.

- `GET SERVERS`, which will return information about the server
- `SET SERVER $idx`, which sets the current server

In linux socat demo

<img src="https://i.imgur.com/dlFuKtg.png" width="512" />

Also, the system tray is supported, see below

## System Tray

Default compile binary without GUI, take parameter `-DWITH_APPLET=ON` to enable system tray.

> cmake -DCMAKE_BUILD_TYPE=Release -DWITH_APPLET=ON . && make

### Linux 

<img src="https://i.imgur.com/Ny0WMJA.png" width="512" />

To show the icon, put `logo/icon.svg` to where pegas sit.


### OSX

<img src="https://i.imgur.com/jOA04aU.png" width="512" />

On OSX, the binary will be packaged into an app bundle by default, just copy the packaged `build/PegasApp.app` to the application directly.

⚠️Note: If you encounter a situation where you can't start or hit a crash, please make sure that

1. the latest libevent is installed in your system (do it manually, libevent2.12 from homebew will cause [this issue](https://github.com/chux0519/pegasocks/issues/23))
2. if there is a **configuration** file, the app bundle will detect `~/.config/.pegasrc` or `~/.config/pegas/config`
