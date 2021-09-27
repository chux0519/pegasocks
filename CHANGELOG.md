## 20201218

- remove bundle script, use cmake to generate app bundle on OSX.
- change default configuration from `~/.pegasrc` to `~/.config/.pegasrc` on OSX

## 20210809

- support UDP
- ssl config changed, sni is supported now, by specifying `ssl.sni`
- remove deprecated methods of openssl and json-c

## 20210921

- support ACL
- support mbedtls
- support jemalloc
- use git submodule to manage dependencies

## 20210927

- implemented shadowsocks protocol (UDP and plugin features will be implemented later)
- support more ciphers, currently, `aes-128-cfb`, `aes-128-gcm`, `aes-256-gcm` and `chacha20-poly1305` are supported
- clean code and file structure change (for better maintenance)
- ci updates for mbedtls build test
- bugfixes
