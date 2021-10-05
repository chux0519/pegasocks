#ifndef _PGS_DEFS_H
#define _PGS_DEFS_H

#include <string.h>

#include <event2/bufferevent.h>

#define BUFSIZE_512 512
#define BUFSIZE_16K 16 * 1024
#define BUFSIZE_4K 4 * 1024
#define MAX_LOG_MPSC_SIZE 64
#define memzero(buf, n) (void)memset(buf, 0, n)

#define SS_INFO "ss-subkey"

#define SOCKS5_CMD_IPV4 0x01
#define SOCKS5_CMD_IPV6 0x04
#define SOCKS5_CMD_HOSTNAME 0x03

#define container_of(ptr, type, member)                                        \
	({                                                                     \
		const typeof(((type *)0)->member) *__mptr = (ptr);             \
		(type *)((char *)__mptr - offsetof(type, member));             \
	})

typedef void(on_event_cb)(struct bufferevent *bev, short events, void *ctx);
typedef void(on_read_cb)(struct bufferevent *bev, void *ctx);
typedef void(on_udp_read_cb)(int fd, short event, void *ctx);

// for older version of libevent
#ifndef evuser_new
#define evuser_new(b, cb, arg) event_new((b), -1, 0, (cb), (arg))
#define evuser_del(ev) event_del(ev)
#define evuser_pending(ev, tv) event_pending((ev), 0, (tv))
#define evuser_initialized(ev) event_initialized(ev)
#define evuser_trigger(ev) event_active((ev), 0, 0)
#endif

#endif
