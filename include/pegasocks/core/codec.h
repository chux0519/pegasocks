#ifndef _PGS_CODEC_H
#define _PGS_CODEC_H

#include <arpa/inet.h>
#include <event2/buffer.h>
#include <stdint.h>

#include "defs.h"
#include "session.h"

#ifndef htonll
#define htonll(x)                                                              \
	((1 == htonl(1)) ?                                                     \
		       (x) :                                                         \
		       ((uint64_t)htonl((x)&0xFFFFFFFF) << 32) | htonl((x) >> 32))
#endif

#ifndef ntohll
#define ntohll(x) htonll(x)
#endif

#define pgs_ws_write_head_text(b, l) pgs_ws_write_head(b, l, 0x01)
#define pgs_ws_write_head_bin(b, l) pgs_ws_write_head(b, l, 0x02)
#define pgs_ws_write_text(b, msg, l) pgs_ws_write(b, msg, l, 0x01)
#define pgs_ws_write_bin(b, msg, l) pgs_ws_write(b, msg, l, 0x02)

typedef void (*pgs_session_write_fn)(pgs_session_t *, uint8_t *, size_t);

/* websocket */

typedef struct pgs_ws_resp_s {
	int fin;
	int opcode;
	int mask;
	uint64_t payload_len; /* for vmess and trojan, size_t is big enough */
	size_t header_len;
} pgs_ws_resp_t;

void pgs_ws_req(struct evbuffer *out, const char *hostname,
		const char *server_address, int server_port, const char *path);
bool pgs_ws_upgrade_check(const char *data);
void pgs_ws_write_head(struct evbuffer *buf, uint64_t len, int opcode);
void pgs_ws_write(struct evbuffer *buf, uint8_t *msg, uint64_t len, int opcode);
bool pgs_ws_parse_head(uint8_t *data, uint64_t data_len, pgs_ws_resp_t *meta);

/* vmess */

typedef struct pgs_vmess_resp_s {
	uint8_t v;
	uint8_t opt;
	uint8_t cmd;
	uint8_t m;
} pgs_vmess_resp_t;

size_t pgs_vmess_write_remote(pgs_session_t *session, const uint8_t *data,
			      size_t data_len);
bool pgs_vmess_parse(pgs_session_t *session, const uint8_t *data,
		     size_t data_len);

size_t pgs_vmess_write_head(pgs_session_t *session,
			    pgs_outbound_ctx_v2ray_t *ctx);
size_t pgs_vmess_write_body(pgs_session_t *session, const uint8_t *data,
			    size_t data_len, size_t head_len,
			    pgs_session_write_fn flush);
bool pgs_vmess_parse_cfb(pgs_session_t *session, const uint8_t *data,
			 size_t data_len, pgs_session_write_fn flush);
bool pgs_vmess_parse_aead(pgs_session_t *session, const uint8_t *data,
			  size_t data_len, pgs_session_write_fn flush);

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

void trojan_write_remote(pgs_session_t *session, uint8_t *msg, size_t len);

void trojan_write_local(pgs_session_t *session, uint8_t *msg, size_t len);

#endif
