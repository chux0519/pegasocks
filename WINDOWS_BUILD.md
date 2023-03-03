## Windows Build Instructions

Windows is not supported by design, but with WSL/mingw, we can compile it on windows.


## MSYS2-UCRT64

Tested on msys2-ucrt64

## Dependencies

> pacman -S mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-openssl pkg-config autoconf automake libtool pkg-config mingw-w64-ucrt-x86_64-mbedtls

Then I recommend build libevent your self, just use the same toolchain as well.

Suppose we have the libevent compiled and installed it to `/c/Users/Bob/repos/libevent/build/dist`

## Compile

Let's say build in the `./build` folder and install path is `./install`

> mkdir -p ./build && mkdir -p ./install

Then

```bash
cd build

cmake -DLibevent2_ROOT=/c/Users/Bob/repos/libevent/build/dist -DWITH_APPLET=ON \
    -DCMAKE_INSTALL_PREFIX=../install \
    -DCMAKE_BUILD_TYPE=Release ..

cmake --build .

cmake --install . --prefix "../install"
```

At last, we copy other used-dlls from ucrt64 (like `libwinpthread`, `libssl` and `libcrypto`)


```bash
cd ../install/bin
ldd pegas.exe  | grep ucrt64 | awk -F\> '{print $2}' | awk -F ' ' '{print $1}' | xargs -I {} cp {} ./
```

Then put your `config.json` into the `bin` directory, double click `pegas.exe` and it will work.
