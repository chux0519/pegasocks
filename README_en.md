<img src="./logo/icon.svg" width="150" align="left" />

# pegasocks [![Cirrus CI Build Status](https://api.cirrus-ci.com/github/chux0519/pegasocks.svg)](https://cirrus-ci.com/github/chux0519/pegasocks)

is a (socks5)proxy client written in C, intended to support multiple types of proxy protocols(trojan, v2ray, ..).
It is lightweight and supports unix-like systems(Linux/WSL/BSDs/OSX).

⚠️ This project is under development, please consider the cost and risk of use at your own discretion.

[中文](./README.md) | English

## Features

Unlike most other clients that support multiple protocols, pegasocks does not rely on various third-party cores (e.g. v2ray-core, etc.), but really goes for the disassembly of the relevant protocols and takes care of performance as much as possible. Therefore it

1. 🍃 is light enough that there are no QT or boost or other third-party binary dependencies.
2. 🚀 Performance-first, with multiple worker threads by default, so theoretically higher throughput to be benchmarked)
3. 🚥 This is a learn by doing project, feel free to review the code, provide optimization ideas and C programming related guidance.
4. ❌ There is no GUI, you can directly work with systemd, launchd, rc or various custom scripts toconfigure the bootu.But you can optianly choose to build a simple tray indicator to interact with it, but in short, a heavy-duty GUI is not under consideration.

## Dependencies

- openssl 1.1.1
- libevent2
- json-c

## Build

> mkdir build && cd build
>
> cmake -DCMAKE_BUILD_TYPE=Release .. && make


Note: The latest openssl in the `/usr/local/Cellar/openssl@1.1/` directory is detected as the openssl root directory by default on OSX systems. In addition, manual setting of cmake parameters is supported

> -DOpenSSLx_ROOT=/xxxxxx/xxx/xxx for openssl root
> 
> -DLibevent2_ROOT=xxxxxx  for libevent root


## Run

> pegas -c config.json -t 4

- `-c` specifies the configuration file, by default it will try `$XDG_CONFIG_HOME/.pegasrc` or `$XDG_CONFIG_HOME/pegas/config` in order 
- `-t` specifies the number of worker threads, default is 4

## Configuration

see [wiki](https://github.com/chux0519/pegasocks/wiki/%E9%85%8D%E7%BD%AE%E8%AF%B4%E6%98%8E)


## Interaction

After the program starts, it listens to `/tmp/pegas.sock` by default (configurable to support both TCP ports and unix sockets), and can interact with the main program through unix sockets. The supported commands are.

- `GET SERVERS`, which will return information about the server
- `SET SERVER $idx`, which sets the current server

In linux socat demo

<img src="https://i.imgur.com/dlFuKtg.png" width="512" />

Also, the system tray is supported, see below

## System Tray

Default compile binary without GUI, take parameter `-DWITH_APPLET=1` to enable system tray.

> cmake -DCMAKE_BUILD_TYPE=Release -DWITH_APPLET=1 . && make

### Linux 

<img src="https://i.imgur.com/Ny0WMJA.png" width="512" />

When booting from the command line, put `logo/icon.svg` into the pegas sibling directory and use it normally.


### OSX

<img src="https://i.imgur.com/jOA04aU.png" width="512" />

When run from the command line, put `logo/icon.png` in the pegas sibling directory and use it as normal.

On OSX, the binary will be packaged into an app bundle by default, just copy the packaged `build/PegasApp.app` to the application directly.

⚠️Note: If you encounter a situation where you can't start, please make sure that

1. libevent and json-c are installed on your system (brew install libevent json-c)
2. if there is a **configuration** file, the app bundle will detect `~/.config/.pegasrc`
