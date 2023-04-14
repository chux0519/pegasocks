#include "session/filter.h"
#include <stdlib.h>

static bool ws_encode(void *ctx, const uint8_t *msg, size_t len, uint8_t **out,
		      size_t *olen)
{
	uint8_t *buff;
	pgs_ws_filter_ctx_t *tfctx = ctx;
	size_t offset = 0;
	if (!tfctx->handshake_ok) {
	} else {
	}
	return true;
}
static bool ws_decode(void *ctx, const uint8_t *msg, size_t len, uint8_t **out,
		      size_t *olen)
{
	// do nothing, skip
	*olen = 0;
	return true;
}

static bool trojan_encode(void *ctx, const uint8_t *msg, size_t len,
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

	return true;
}
static bool trojan_decode(void *ctx, const uint8_t *msg, size_t len,
			  uint8_t **out, size_t *olen)
{
	// do nothing, skip
	*olen = 0;
	return true;
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
	case (FITLER_WEBSOCKET): {
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
	ptr->head[sha224_pass_len + 2] = cmd[1];
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
	ptr->handshake_ok = false;

	return ptr;
}
void pgs_ws_filter_ctx_free(pgs_ws_filter_ctx_t *ptr)
{
	if (!ptr)
		return;

	free(ptr);
}