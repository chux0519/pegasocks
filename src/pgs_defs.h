#ifndef _PGS_DEFS
#define _PGS_DEFS

#include <string.h>

#include <event2/bufferevent.h>

#define BUFSIZE_512 512
#define BUFSIZE_16K 16 * 1024
#define BUFSIZE_4K 4 * 1024
#define memzero(buf, n) (void)memset(buf, 0, n)

#define SOCKS5_CMD_IPV4 0x01
#define SOCKS5_CMD_IPV6 0x04
#define SOCKS5_CMD_HOSTNAME 0x03

typedef void(on_event_cb)(struct bufferevent *bev, short events, void *ctx);
typedef void(on_read_cb)(struct bufferevent *bev, void *ctx);
typedef void(on_udp_read_cb)(int fd, short event, void *ctx);

#endif
