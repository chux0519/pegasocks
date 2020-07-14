#ifndef _PGS_CODEC
#define _PGS_CODEC

#include "pgs_core.h"
#include "pgs_ev.h"
#include "pgs_session.h"

#define pgs_ws_write_head_text(b, l) pgs_ws_write_head(b, l, 0x01)
#define pgs_ws_write_head_bin(b, l) pgs_ws_write_head(b, l, 0x02)
#define pgs_ws_write_text(b, msg, l) pgs_ws_write(b, msg, l, 0x01)
#define pgs_ws_write_bin(b, msg, l) pgs_ws_write(b, msg, l, 0x02)

typedef struct pgs_ws_resp_s pgs_ws_resp_t;

/* for ws response header */
struct pgs_ws_resp_s {
	int fin;
	int opcode;
	int mask;
	uint64_t payload_len;
	size_t header_len;
};

/* websocket */
void pgs_ws_req(pgs_evbuffer_t *out, const char *hostname,
		const char *server_address, int server_port, const char *path);
bool pgs_ws_upgrade_check(const char *data);
void pgs_ws_write_head(pgs_evbuffer_t *buf, pgs_size_t len, int opcode);
void pgs_ws_write(pgs_evbuffer_t *buf, pgs_buf_t *msg, pgs_size_t len,
		  int opcode);
bool pgs_ws_parse_head(pgs_buf_t *data, pgs_size_t data_len,
		       pgs_ws_resp_t *meta);

/* vmess */
pgs_size_t pgs_vmess_write_head(const pgs_buf_t *uuid, pgs_vmess_ctx_t *ctx);

pgs_size_t pgs_vmess_write_body(pgs_buf_t *buf, pgs_evbuffer_t *inboundr,
				pgs_vmess_ctx_t *ctx);

bool pgs_vmess_parse(pgs_buf_t *data, pgs_size_t data_len, pgs_vmess_ctx_t *ctx,
		     pgs_evbuffer_t *writer);
#endif
