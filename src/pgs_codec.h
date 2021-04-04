#ifndef _PGS_CODEC
#define _PGS_CODEC

#include <event2/buffer.h>
#include <stdint.h>

#include "pgs_defs.h"
#include "pgs_session.h"

#define pgs_ws_write_head_text(b, l) pgs_ws_write_head(b, l, 0x01)
#define pgs_ws_write_head_bin(b, l) pgs_ws_write_head(b, l, 0x02)
#define pgs_ws_write_text(b, msg, l) pgs_ws_write(b, msg, l, 0x01)
#define pgs_ws_write_bin(b, msg, l) pgs_ws_write(b, msg, l, 0x02)

typedef struct pgs_ws_resp_s pgs_ws_resp_t;
typedef void *(*pgs_vmess_write_body_cb)(struct evbuffer *, uint8_t *,
					 uint64_t);

/* for ws response header */
struct pgs_ws_resp_s {
	int fin;
	int opcode;
	int mask;
	uint64_t payload_len;
	size_t header_len;
};

/* socks5 */
bool pgs_socks5_handshake(pgs_session_t *session);
char *socks5_dest_addr_parse(const uint8_t *cmd, uint64_t cmd_len);

/* websocket */
void pgs_ws_req(struct evbuffer *out, const char *hostname,
		const char *server_address, int server_port, const char *path);
bool pgs_ws_upgrade_check(const char *data);
void pgs_ws_write_head(struct evbuffer *buf, uint64_t len, int opcode);
void pgs_ws_write(struct evbuffer *buf, uint8_t *msg, uint64_t len, int opcode);
bool pgs_ws_parse_head(uint8_t *data, uint64_t data_len, pgs_ws_resp_t *meta);

/* vmess */
uint64_t pgs_vmess_write_head(const uint8_t *uuid, pgs_vmess_ctx_t *ctx);

uint64_t pgs_vmess_write_body(const uint8_t *data, uint64_t data_len,
			      uint64_t head_len, pgs_vmess_ctx_t *ctx,
			      struct evbuffer *writer,
			      pgs_vmess_write_body_cb cb);

uint64_t pgs_vmess_write(const uint8_t *password, const uint8_t *data,
			 uint64_t data_len, pgs_vmess_ctx_t *ctx,
			 struct evbuffer *writer, pgs_vmess_write_body_cb cb);

bool pgs_vmess_parse(const uint8_t *data, uint64_t data_len,
		     pgs_vmess_ctx_t *ctx, struct evbuffer *writer);
bool pgs_vmess_parse_cfb(const uint8_t *data, uint64_t data_len,
			 pgs_vmess_ctx_t *ctx, struct evbuffer *writer);
bool pgs_vmess_parse_gcm(const uint8_t *data, uint64_t data_len,
			 pgs_vmess_ctx_t *ctx, struct evbuffer *writer);
#endif
