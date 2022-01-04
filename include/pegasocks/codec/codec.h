#ifndef _PGS_CODEC_H
#define _PGS_CODEC_H

#include "defs.h"
#include "websocket.h"
#include "vmess.h"
#include "trojan.h"
#include "shadowsocks.h"

#ifndef htonll
#define htonll(x)                                                              \
	((1 == htonl(1)) ?                                                     \
		       (x) :                                                         \
		       ((uint64_t)htonl((x)&0xFFFFFFFF) << 32) | htonl((x) >> 32))
#endif

#ifndef ntohll
#define ntohll(x) htonll(x)
#endif

// static helper functions
static inline int pgs_get_addr_len(const uint8_t *data)
{
	switch (data[0] /*atype*/) {
	case 0x01:
		// IPv4
		return 4;
	case 0x03:
		return 1 + data[1];
	case 0x04:
		// IPv6
		return 16;
	default:
		break;
	}
	return 0;
}

#endif
