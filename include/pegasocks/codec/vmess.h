#ifndef _PGS_CODEC_VMESS_H
#define _PGS_CODEC_VMESS_H

#include "session/session.h"

typedef void (*pgs_session_write_fn)(pgs_session_t *, uint8_t *, size_t);

typedef struct pgs_vmess_resp_s {
	uint8_t v;
	uint8_t opt;
	uint8_t cmd;
	uint8_t m;
} pgs_vmess_resp_t;

bool vmess_write_remote(pgs_session_t *session, const uint8_t *data,
			size_t data_len, size_t *olen);
bool vmess_write_local(pgs_session_t *session, const uint8_t *data,
		       size_t data_len, size_t *olen);

#endif
