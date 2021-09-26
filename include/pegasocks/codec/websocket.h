#ifndef _PGS_CODEC_WEBSOCKET_H
#define _PGS_CODEC_WEBSOCKET_H

#include "session/session.h"

#define pgs_ws_write_head_text(b, l) pgs_ws_write_head(b, l, 0x01)
#define pgs_ws_write_head_bin(b, l) pgs_ws_write_head(b, l, 0x02)
#define pgs_ws_write_text(b, msg, l) pgs_ws_write(b, msg, l, 0x01)
#define pgs_ws_write_bin(b, msg, l) pgs_ws_write(b, msg, l, 0x02)

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

#endif
