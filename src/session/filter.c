#include "session/filter.h"
#include <stdlib.h>

static int ws_encode(void *ctx, const uint8_t *msg, size_t len, uint8_t **out,
		     size_t *olen)
{
	pgs_ws_filter_ctx_t *wsctx = ctx;

	uint8_t *buf = NULL;

	uint8_t a = 0;
	a |= 1 << 7; //fin
	a |= wsctx->opcode;

	uint8_t b = 0;
	b |= 1 << 7; //mask

	uint16_t c = 0;
	uint64_t d = 0;

	//payload len
	if (len < 126) {
		b |= len;
	} else if (len < (1 << 16)) {
		b |= 126;
		c = htons(len);
	} else {
		b |= 127;
		d = htonll(len);
	}

	if (c)
		buf = malloc(sizeof(uint8_t) * (4 + len + 4));
	else if (d)
		buf = malloc(sizeof(uint8_t) * (10 + len + 4));
	else
		buf = malloc(sizeof(uint8_t) * (2 + len + 4));

	assert(buf != NULL);

	size_t offset = 0;
	memcpy(buf + offset, &a, 1);
	offset += 1;
	memcpy(buf + offset, &b, 1);
	offset += 1;

	if (c) {
		memcpy(buf + offset, &c, 2);
		offset += 2;
	} else if (d) {
		memcpy(buf + offset, &d, 8);
		offset += 8;
	}

	uint8_t mask_key[4] = { 0 };
	memcpy(buf + offset, &mask_key, 4);
	offset += 4;

	/* header end */

	memcpy(buf + offset, msg, len);
	offset += len;

	*olen = offset;

	*out = buf;

	return FILTER_SUCCESS;
}
static int ws_decode(void *ctx, const uint8_t *msg, size_t len, uint8_t **out,
		     size_t *olen, size_t *clen)
{
	pgs_ws_filter_ctx_t *wsctx = ctx;

	wsctx->header.fin = !!(*msg & 0x80);
	wsctx->header.opcode = *msg & 0x0F;
	wsctx->header.mask = !!(*(msg + 1) & 0x80);
	wsctx->header.payload_len = *(msg + 1) & 0x7F;
	wsctx->header.header_len = 2 + (wsctx->header.mask ? 4 : 0);

	if (wsctx->header.payload_len < 126) {
		if (wsctx->header.header_len > len)
			return FILTER_NEED_MORE_DATA;
	} else if (wsctx->header.payload_len == 126) {
		wsctx->header.header_len += 2;
		if (wsctx->header.header_len > len)
			return FILTER_NEED_MORE_DATA;

		wsctx->header.payload_len = ntohs(*(uint16_t *)(msg + 2));

	} else if (wsctx->header.payload_len == 127) {
		wsctx->header.header_len += 8;
		if (wsctx->header.header_len > len)
			return FILTER_NEED_MORE_DATA;

		wsctx->header.payload_len = ntohll(*(uint64_t *)(msg + 2));
	}

	if (wsctx->header.header_len + wsctx->header.payload_len > len)
		return FILTER_NEED_MORE_DATA;

	const unsigned char *mask_key = msg + wsctx->header.header_len - 4;

	uint8_t *buf = malloc(sizeof(uint8_t) * wsctx->header.payload_len);
	memcpy(buf, msg + wsctx->header.header_len, wsctx->header.payload_len);
	for (int i = 0; wsctx->header.mask && (i < wsctx->header.payload_len);
	     i++)
		buf[i] = msg[wsctx->header.header_len + i] ^ mask_key[i % 4];

	*olen = wsctx->header.payload_len;

	*out = buf;

	*clen = wsctx->header.header_len + wsctx->header.payload_len;

	return FILTER_SUCCESS;
}

static int trojan_encode(void *ctx, const uint8_t *msg, size_t len,
			 uint8_t **out, size_t *olen)
{
	uint8_t *buff;
	pgs_trojan_filter_ctx_t *tfctx = ctx;
	size_t offset = 0;
	if (!tfctx->head_sent) {
		tfctx->head_sent = true;

		buff = malloc(sizeof(uint8_t) * (tfctx->head_len + len));
		memcpy(buff, tfctx->head, tfctx->head_len);
		offset += tfctx->head_len;
	} else {
		buff = malloc(sizeof(uint8_t) * len);
	}
	memcpy(buff + offset, msg, len);
	offset += len;

	*olen = offset;
	*out = buff;

	return FILTER_SUCCESS;
}
static int trojan_decode(void *ctx, const uint8_t *msg, size_t len,
			 uint8_t **out, size_t *olen, size_t *clen)
{
	if (*clen < len)
		*clen = len;
	return FILTER_SKIP;
}

static int trojan_udp_encode(void *ctx, const uint8_t *msg, size_t len,
			     uint8_t **out, size_t *olen)
{
	const pgs_socks5_cmd_t *cmd = ctx;
	/*
	+------+----------+----------+--------+---------+----------+
	| ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload  |
	+------+----------+----------+--------+---------+----------+
	|  1   | Variable |    2     |   2    | X'0D0A' | Variable |
	+------+----------+----------+--------+---------+----------+
	*/
	size_t len1 = cmd->cmd_len - 3; /*RSV(2) | FRAG(1) |*/
	size_t buf_len = len1 + 2 + 2 + len;
	uint8_t *buf = malloc(sizeof(uint8_t) * buf_len);
	memcpy(buf, cmd->raw_cmd + 3, len1);
	buf[len1] = len >> 8;
	buf[len1 + 1] = len & 0xFF;
	buf[len1 + 2] = '\r';
	buf[len1 + 3] = '\n';
	memcpy(buf + len1 + 2 + 2, msg, len);

	*out = buf;
	*olen = buf_len;

	return FILTER_SUCCESS;
}

static int trojan_udp_decode(void *ctx, const uint8_t *msg, size_t len,
			     uint8_t **out, size_t *olen, size_t *clen)
{
	uint8_t atype = msg[0];
	size_t len1 = 1 + 2; /* atype(1) + len(dst) + port(2)*/
	switch (atype) {
	case 0x01: {
		// IPv4
		len1 += 4;
		break;
	}
	case 0x03: {
		len1 += (1 + msg[1]);
		break;
	}
	case 0x04: {
		// IPv6
		len1 += 16;
		break;
	}
	default:
		break;
	}
	uint16_t payload_len = msg[len1] << 8 | msg[len1 + 1];
	if (len < (len1 + 2 /*length*/ + 2 /*CRLF*/ + payload_len) ||
	    msg[len1 + 2] != '\r' || msg[len1 + 3] != '\n') {
		return FILTER_FAIL;
	}

	uint8_t *buf = malloc(sizeof(uint8_t) * payload_len);
	memcpy(buf, msg + len1 + 2 + 2, payload_len);

	*out = buf;
	*olen = payload_len;
	*clen = len;

	return FILTER_SUCCESS;
}

pgs_filter_t *pgs_filter_new(pgs_filter_type type, const pgs_session_t *session)
{
	pgs_filter_t *ptr = malloc(sizeof(pgs_filter_t));
	ptr->type = type;

	switch (type) {
	case (FILTER_TROJAN): {
		ptr->ctx = pgs_trojan_filter_ctx_new(session);
		ptr->free = (void *)pgs_trojan_filter_ctx_free;
		ptr->encode = trojan_encode;
		ptr->decode = trojan_decode;
		break;
	}
	case (FITLER_TROJAN_UDP): {
		ptr->ctx = (void *)&session->cmd;
		ptr->free = NULL;
		ptr->encode = trojan_udp_encode;
		ptr->decode = trojan_udp_decode;
		break;
	}
	case (FITLER_WEBSOCKET): {
		ptr->ctx = pgs_ws_filter_ctx_new(session);
		ptr->free = (void *)pgs_ws_filter_ctx_free;
		ptr->encode = ws_encode;
		ptr->decode = ws_decode;
		break;
	}
	default:
		break;
	}
	return ptr;
}

void pgs_filter_free(pgs_filter_t *ptr)
{
	if (!ptr)
		return;
	if (ptr->ctx && ptr->free)
		ptr->free(ptr->ctx);
	free(ptr);
}

pgs_trojan_filter_ctx_t *pgs_trojan_filter_ctx_new(const pgs_session_t *session)
{
	/**
	+-----------------------+---------+----------------+---------+----------+
	| hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
	+-----------------------+---------+----------------+---------+----------+
	|          56           | X'0D0A' |    Variable    | X'0D0A' | Variable |
	+-----------------------+---------+----------------+---------+----------+

	where Trojan Request is a SOCKS5-like request:

	+-----+------+----------+----------+
	| CMD | ATYP | DST.ADDR | DST.PORT |
	+-----+------+----------+----------+
	|  1  |  1   | Variable |    2     |
	+-----+------+----------+----------+
	*/
	pgs_trojan_filter_ctx_t *ptr = malloc(sizeof(pgs_trojan_filter_ctx_t));
	ptr->head_sent = false;

	const uint8_t *sha224_pass = session->config->password;
	size_t sha224_pass_len = SHA224_LEN * 2;

	const uint8_t *cmd = session->cmd.raw_cmd;
	size_t cmd_len = session->cmd.cmd_len;

	// sha224(password) + "\r\n" + cmd[1] + cmd.substr(3) + "\r\n"
	ptr->head_len = sha224_pass_len + 2 + 1 + cmd_len - 3 + 2;
	ptr->head = (char *)malloc(sizeof(char) * ptr->head_len);

	memcpy(ptr->head, sha224_pass, sha224_pass_len);
	ptr->head[sha224_pass_len] = '\r';
	ptr->head[sha224_pass_len + 1] = '\n';
	ptr->head[sha224_pass_len + 2] = session->outbound.protocol;
	memcpy(ptr->head + sha224_pass_len + 3, cmd + 3, cmd_len - 3);
	ptr->head[ptr->head_len - 2] = '\r';
	ptr->head[ptr->head_len - 1] = '\n';

	return ptr;
}
void pgs_trojan_filter_ctx_free(pgs_trojan_filter_ctx_t *ptr)
{
	if (!ptr)
		return;
	if (ptr->head)
		free(ptr->head);
	free(ptr);
}

pgs_ws_filter_ctx_t *pgs_ws_filter_ctx_new(const pgs_session_t *session)
{
	pgs_ws_filter_ctx_t *ptr = malloc(sizeof(pgs_ws_filter_ctx_t));
	ptr->opcode = 0x01; /* text */

	const pgs_server_config_t *config = session->config;

	if (IS_TROJAN_SERVER(config->server_type)) {
		ptr->opcode = 0x01; /* text */
	} else if (IS_V2RAY_SERVER(config->server_type)) {
		ptr->opcode = 0x02; /* bin */
	}

	return ptr;
}
void pgs_ws_filter_ctx_free(pgs_ws_filter_ctx_t *ptr)
{
	if (!ptr)
		return;

	free(ptr);
}