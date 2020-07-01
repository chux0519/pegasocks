#ifndef _PGS_CODEC
#define _PGS_CODEC

#include "pgs_core.h"
#include "pgs_ev.h"

typedef struct pgs_ws_meta_s pgs_ws_meta_t;

struct pgs_ws_meta_s {
	int fin;
	int opcode;
	int mask;
	uint64_t payload_len;
	size_t header_len;
};

void pgs_ws_req(pgs_evbuffer_t *out, const char *hostname,
		const char *server_address, int server_port, const char *path);

bool pgs_ws_upgrade_check(const char *data);

void pgs_ws_write_head(pgs_evbuffer_t *buf, pgs_size_t len);

bool pgs_ws_parse_head(pgs_buf_t *data, pgs_size_t data_len,
		       pgs_ws_meta_t *meta);

void pgs_ws_write(pgs_evbuffer_t *buf, pgs_buf_t *msg, pgs_size_t len);

#endif
