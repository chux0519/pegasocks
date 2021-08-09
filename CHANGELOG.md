## 20201218

- remove bundle script, use cmake to generate app bundle on OSX.
- change default configuration from `~/.pegasrc` to `~/.config/.pegasrc` on OSX

## 20210809

- support UDP
- ssl config changed, sni is supported now, by specifying `ssl.sni`
- remove deprecated methods of openssl and json-c
