#ifndef _PGS_CODEC_SHADOWSOCKS_H
#define _PGS_CODEC_SHADOWSOCKS_H

#include "session/session.h"

bool shadowsocks_write_remote(pgs_session_t *session, const uint8_t *msg,
			      size_t len, size_t *olen);
bool shadowsocks_write_local(pgs_session_t *session, const uint8_t *msg,
			     size_t len, size_t *olen);

#endif
