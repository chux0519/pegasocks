#include "pgs_codec.h"
#include "pgs_util.h"
#include <assert.h>
#include <openssl/rand.h>

#define htonll(x)                                                              \
	((1 == htonl(1)) ?                                                     \
		 (x) :                                                         \
		 ((uint64_t)htonl((x)&0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) htonll(x)

const char *ws_key = "dGhlIHNhbXBsZSBub25jZQ==";
const char *ws_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
const char vmess_key_suffix[36] = "c48619fe-8f02-49e0-b9e9-edf763e17e21";

void pgs_ws_req(pgs_evbuffer_t *out, const char *hostname,
		const char *server_address, int server_port, const char *path)
{
	// out, hostname, server_address, server_port, path
	pgs_evbuffer_add_printf(out, "GET %s HTTP/1.1\r\n", path);
	pgs_evbuffer_add_printf(out, "Host:%s:%d\r\n", hostname, server_port);
	pgs_evbuffer_add_printf(out, "Upgrade:websocket\r\n");
	pgs_evbuffer_add_printf(out, "Connection:upgrade\r\n");
	pgs_evbuffer_add_printf(out, "Sec-WebSocket-Key:%s\r\n", ws_key);
	pgs_evbuffer_add_printf(out, "Sec-WebSocket-Version:13\r\n");
	pgs_evbuffer_add_printf(
		out, "Origin:https://%s:%d\r\n", server_address,
		server_port); //missing this key will lead to 403 response.
	pgs_evbuffer_add_printf(out, "\r\n");
}

bool pgs_ws_upgrade_check(const char *data)
{
	return strncmp(data, "HTTP/1.1 101", strlen("HTTP/1.1 101")) != 0 ||
	       !strstr(data, ws_accept);
}

void pgs_ws_write(pgs_evbuffer_t *buf, pgs_buf_t *msg, pgs_size_t len,
		  int opcode)
{
	pgs_ws_write_head(buf, len, opcode);
	// x ^ 0 = x
	pgs_evbuffer_add(buf, msg, len);
}

void pgs_ws_write_head(pgs_evbuffer_t *buf, pgs_size_t len, int opcode)
{
	uint8_t a = 0;
	a |= 1 << 7; //fin
	a |= opcode;

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

	pgs_evbuffer_add(buf, &a, 1);
	pgs_evbuffer_add(buf, &b, 1);

	if (c)
		pgs_evbuffer_add(buf, &c, sizeof(c));
	else if (d)
		pgs_evbuffer_add(buf, &d, sizeof(d));

	// tls will protect data
	// mask data makes nonsense
	uint8_t mask_key[4] = { 0, 0, 0, 0 };
	pgs_evbuffer_add(buf, &mask_key, 4);
}

bool pgs_ws_parse_head(pgs_buf_t *data, pgs_size_t data_len,
		       pgs_ws_resp_t *meta)
{
	bool parsed = false;

	meta->fin = !!(*data & 0x80);
	meta->opcode = *data & 0x0F;
	meta->mask = !!(*(data + 1) & 0x80);
	meta->payload_len = *(data + 1) & 0x7F;
	meta->header_len = 2 + (meta->mask ? 4 : 0);

	if (meta->payload_len < 126) {
		if (meta->header_len > data_len)
			return parsed;

	} else if (meta->payload_len == 126) {
		meta->header_len += 2;
		if (meta->header_len > data_len)
			return parsed;

		meta->payload_len = ntohs(*(uint16_t *)(data + 2));

	} else if (meta->payload_len == 127) {
		meta->header_len += 8;
		if (meta->header_len > data_len)
			return parsed;

		meta->payload_len = ntohll(*(uint64_t *)(data + 2));
	}

	if (meta->header_len + meta->payload_len > data_len)
		return parsed;

	const unsigned char *mask_key = data + meta->header_len - 4;

	for (int i = 0; meta->mask && i < meta->payload_len; i++)
		data[meta->header_len + i] ^= mask_key[i % 4];

	parsed = true;
	return parsed;
}

pgs_size_t pgs_vmess_write_head(const pgs_buf_t *uuid, pgs_vmess_ctx_t *ctx)
{
	pgs_buf_t *buf = ctx->remote_wbuf;
	pgs_buf_t *socks5_cmd = (pgs_buf_t *)ctx->cmd;
	pgs_size_t socks5_cmd_len = ctx->cmdlen;
	time_t now = time(NULL);
	unsigned long ts = htonll(now);
	pgs_buf_t header_auth[16];
	pgs_size_t header_auth_len = 0;
	hmac_md5(uuid, 16, (const pgs_buf_t *)&ts, 8, header_auth,
		 &header_auth_len);
	assert(header_auth_len == 16);
	pgs_memcpy(buf, header_auth, header_auth_len);

	// socks5 cmd
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	//
	// vmess header
	int n = socks5_cmd_len - 4 - 2;
	int p = 0;
	pgs_size_t header_cmd_len =
		1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + n + p + 4;
	pgs_buf_t header_cmd_raw[header_cmd_len];
	pgs_buf_t header_cmd_encoded[header_cmd_len];
	pgs_memzero(header_cmd_raw, header_cmd_len);
	pgs_memzero(header_cmd_encoded, header_cmd_len);

	int offset = 0;
	// ver
	header_cmd_raw[0] = 1;
	offset += 1;
	// data iv
	RAND_bytes(header_cmd_raw + offset, AES_128_CFB_IV_LEN);
	pgs_memcpy(ctx->iv, header_cmd_raw + offset, AES_128_CFB_IV_LEN);
	offset += AES_128_CFB_KEY_LEN;
	// data key
	RAND_bytes(header_cmd_raw + offset, AES_128_CFB_KEY_LEN);
	pgs_memcpy(ctx->key, header_cmd_raw + offset, AES_128_CFB_KEY_LEN);
	offset += AES_128_CFB_IV_LEN;
	// v
	offset += RAND_bytes(header_cmd_raw + offset, 1);
	// standard format data
	header_cmd_raw[offset] = 0x01;
	offset += 1;
	// aes 126 cfb
	header_cmd_raw[offset] = 0x00;
	offset += 1;
	// X
	header_cmd_raw[offset] = 0x00;
	offset += 1;
	// tcp
	header_cmd_raw[offset] = 0x01;
	offset += 1;
	// port
	header_cmd_raw[offset] = socks5_cmd[socks5_cmd_len - 2];
	header_cmd_raw[offset + 1] = socks5_cmd[socks5_cmd_len - 1];
	offset += 2;
	// atype
	if (socks5_cmd[3] == 0x01) {
		header_cmd_raw[offset] = 0x01;
	} else {
		header_cmd_raw[offset] = socks5_cmd[3] - 1;
	}
	offset += 1;
	// addr
	pgs_memcpy(header_cmd_raw + offset, socks5_cmd + 4, n);
	offset += n;

	assert(offset + 4 == header_cmd_len);

	unsigned int f = fnv1a(header_cmd_raw, header_cmd_len - 4);

	header_cmd_raw[offset] = f >> 24;
	header_cmd_raw[offset + 1] = f >> 16;
	header_cmd_raw[offset + 2] = f >> 8;
	header_cmd_raw[offset + 3] = f;

	pgs_buf_t k_md5_input[16 + 36];
	pgs_memcpy(k_md5_input, uuid, 16);
	pgs_memcpy(k_md5_input + 16, vmess_key_suffix, 36);
	pgs_buf_t cmd_k[AES_128_CFB_KEY_LEN];
	md5(k_md5_input, 16 + 36, cmd_k);

	pgs_buf_t iv_md5_input[32];
	now = time(NULL);
	ts = htonll(now);
	pgs_memcpy(iv_md5_input, (const unsigned char *)&ts, 8);
	pgs_memcpy(iv_md5_input + 8, (const unsigned char *)&ts, 8);
	pgs_memcpy(iv_md5_input + 16, (const unsigned char *)&ts, 8);
	pgs_memcpy(iv_md5_input + 24, (const unsigned char *)&ts, 8);
	pgs_buf_t cmd_iv[AES_128_CFB_IV_LEN];
	md5(iv_md5_input, 32, cmd_iv);

	aes_128_cfb_encrypt(header_cmd_raw, header_cmd_len, cmd_k, cmd_iv,
			    header_cmd_encoded);
	pgs_memcpy(buf + header_auth_len, header_cmd_encoded, header_cmd_len);

	return header_auth_len + header_cmd_len;
}

pgs_size_t pgs_vmess_write_body(pgs_buf_t *buf, pgs_evbuffer_t *inboundr,
				pgs_vmess_ctx_t *ctx)
{
	pgs_size_t data_len = pgs_evbuffer_get_length(inboundr);
	unsigned char *data = pgs_evbuffer_pullup(inboundr, data_len);

	pgs_buf_t *localr = ctx->local_rbuf;

	// data section
	assert(data_len + 6 <= _PGS_BUFSIZE);
	localr[0] = (data_len + 4) >> 8;
	localr[1] = (data_len + 4);

	unsigned int f = fnv1a((void *)data, data_len);
	localr[2] = f >> 24;
	localr[3] = f >> 16;
	localr[4] = f >> 8;
	localr[5] = f;

	pgs_memcpy(localr + 6, data, data_len);
	pgs_evbuffer_drain(inboundr, data_len);

	aes_128_cfb_encrypt(localr, data_len + 6,
			    (const unsigned char *)ctx->key,
			    (const unsigned char *)ctx->iv, buf);
	return data_len + 6;
}

bool pgs_vmess_parse(pgs_buf_t *data, pgs_size_t data_len, pgs_vmess_ctx_t *ctx,
		     pgs_evbuffer_t *writer)
{
	pgs_vmess_resp_t *meta = &ctx->resp_meta;

	pgs_buf_t iv[AES_128_CFB_IV_LEN];
	pgs_buf_t key[AES_128_CFB_KEY_LEN];
	md5((const pgs_buf_t *)ctx->iv, AES_128_CFB_IV_LEN, iv);
	md5((const pgs_buf_t *)ctx->key, AES_128_CFB_KEY_LEN, key);

	if (!ctx->header_recved) {
		if (ctx->remote_rbuf_pos == 0) {
			// first package
			if (data_len < 10)
				return false;
			aes_128_cfb_decrypt(data, data_len, key, iv,
					    ctx->remote_rbuf);

			meta->v = ctx->remote_rbuf[0];
			meta->opt = ctx->remote_rbuf[1];
			meta->cmd = ctx->remote_rbuf[2];
			meta->m = ctx->remote_rbuf[3];

			if (meta->cmd == 0x01 || meta->m != 0)
				return false;

			ctx->resp_len = ((ctx->remote_rbuf[4] << 8) |
					 ctx->remote_rbuf[5]) -
					4;
			ctx->resp_hash = ctx->remote_rbuf[6] << 24 |
					 ctx->remote_rbuf[7] << 16 |
					 ctx->remote_rbuf[8] |
					 ctx->remote_rbuf[9];

			// len: 2042, data_len: 2048, head: 4 + m(0) + 6 = 10, remains: 2042 - (2048 - 10) = 4
			pgs_size_t remains_data_len = data_len - 10;
			if (remains_data_len >= ctx->resp_len) {
				// payload is long enough
				aes_128_cfb_decrypt(data, 10 + ctx->resp_len,
						    key, iv, ctx->remote_rbuf);
				pgs_evbuffer_add(writer, ctx->remote_rbuf + 10,
						 ctx->resp_len);
				pgs_memcpy(ctx->remote_rbuf,
					   data + 10 + ctx->resp_len,
					   remains_data_len - ctx->resp_len);
				ctx->remote_rbuf_pos = 0;
			} else {
				// copy to buffer read next time
				pgs_memcpy(ctx->remote_rbuf, data, data_len);
				ctx->remote_rbuf_pos = data_len;
			}

		} else {
			// have remains package
			if (ctx->remote_rbuf_pos + data_len >=
			    ctx->resp_len + 10) {
				pgs_size_t data_to_read = ctx->resp_len + 10 -
							  ctx->remote_rbuf_pos;
				pgs_memcpy(ctx->remote_rbuf +
						   ctx->remote_rbuf_pos,
					   data, data_to_read);
				// enough data
				aes_128_cfb_decrypt(ctx->remote_rbuf,
						    10 + ctx->resp_len, key, iv,
						    ctx->local_wbuf);
				pgs_evbuffer_add(writer, ctx->local_wbuf + 10,
						 ctx->resp_len);
				pgs_memcpy(ctx->remote_rbuf,
					   data + data_to_read,
					   data_len - data_to_read);
				ctx->remote_rbuf_pos = data_len - data_to_read;
				ctx->header_recved = true;
			} else {
				// needs more
				pgs_memcpy(ctx->remote_rbuf +
						   ctx->remote_rbuf_pos,
					   data, data_len);
				ctx->remote_rbuf_pos += data_len;
			}
		}
		return true;

	} else {
		// remains block
		// TODO:
	}
	return true;
}
