#ifndef _PGS_FILTER_H
#define _PGS_FILTER_H

#include "session.h"

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef enum { FILTER_TROJAN = 0, FITLER_WEBSOCKET } pgs_filter_type;
typedef struct pgs_filter_s {
	pgs_filter_type type;

	void *ctx;

	void (*free)(void *ctx);
	bool (*encode)(void *ctx, const uint8_t *msg, size_t len, uint8_t **out,
		       size_t *olen);
	bool (*decode)(void *ctx, const uint8_t *msg, size_t len, uint8_t **out,
		       size_t *olen);
} pgs_filter_t;

pgs_filter_t *pgs_filter_new(pgs_filter_type, const pgs_session_t *);
void pgs_filter_free(pgs_filter_t *);

typedef struct pgs_trojan_filter_ctx_s {
	bool head_sent;
	// sha224(password) + "\r\n" + cmd[1] + cmd.substr(3) + "\r\n"
	char *head;
	size_t head_len;
} pgs_trojan_filter_ctx_t;

pgs_trojan_filter_ctx_t *pgs_trojan_filter_ctx_new(const pgs_session_t *);
void pgs_trojan_filter_ctx_free(pgs_trojan_filter_ctx_t *);

typedef struct pgs_ws_header_s {
	int fin;
	int opcode;
	int mask;
	uint64_t payload_len; /* for vmess and trojan, size_t is big enough */
	size_t header_len;
} pgs_ws_header_t;

typedef struct pgs_ws_filter_ctx_s {
	bool handshake_ok;
	pgs_ws_header_t header;
} pgs_ws_filter_ctx_t;

pgs_ws_filter_ctx_t *pgs_ws_filter_ctx_new(const pgs_session_t *);
void pgs_ws_filter_ctx_free(pgs_ws_filter_ctx_t *);

#endif