#include "pgs_codec.h"
#include "pgs_util.h"
#include "pgs_crypto.h"
#include <assert.h>
#include <openssl/rand.h>

#ifndef htonll
#define htonll(x)                                                              \
	((1 == htonl(1)) ?                                                     \
		 (x) :                                                         \
		 ((uint64_t)htonl((x)&0xFFFFFFFF) << 32) | htonl((x) >> 32))
#endif

#ifndef ntohll
#define ntohll(x) htonll(x)
#endif

const char *ws_key = "dGhlIHNhbXBsZSBub25jZQ==";
const char *ws_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
const char vmess_key_suffix[36] = "c48619fe-8f02-49e0-b9e9-edf763e17e21";

/*
 * Socks5 5 handshake
 * return false if error
 * */
bool pgs_socks5_handshake(pgs_session_t *session)
{
	pgs_bev_t *bev = session->inbound->bev;
	pgs_session_inbound_state state = session->inbound->state;

	pgs_evbuffer_t *output = pgs_bev_get_output(bev);
	pgs_evbuffer_t *input = pgs_bev_get_input(bev);

	pgs_size_t len = pgs_evbuffer_get_length(input);
	unsigned char *rdata = pgs_evbuffer_pullup(input, len);

	pgs_session_debug_buffer(session, rdata, len);

	switch (state) {
	case INBOUND_AUTH:
		if (len < 2 || rdata[0] != 0x5) {
			pgs_session_error(session, "socks5: auth");
			return false;
		}
		pgs_evbuffer_add(output, "\x05\x00", 2);
		pgs_evbuffer_drain(input, len);
		session->inbound->state = INBOUND_CMD;
		return true;
	case INBOUND_CMD: {
		if (len < 7 || rdata[0] != 0x5 || rdata[2] != 0x0) {
			pgs_session_error(session, "socks5: cmd");
			return false;
		}
		switch (rdata[1]) {
		case 0x01: {
			// connect
			uint8_t atype = rdata[3];
			uint16_t port = rdata[len - 2] << 8 | rdata[len - 1];

			int addr_len = 0;
			switch (atype) {
			case 0x01:
				// IPv4
				addr_len = 4;
				break;
			case 0x03:
				// Domain
				addr_len = rdata[4] + 1;
				break;
			case 0x04:
				// IPv6
				addr_len = 16;
				break;
			default:
				pgs_session_error(session,
						  "socks5: wrong atyp");
				return false;
			}
			// Set cmd
			session->inbound->cmdlen = 4 + addr_len + 2;
			session->inbound->cmd = pgs_malloc(
				sizeof(pgs_buf_t) * session->inbound->cmdlen);
			pgs_memcpy(session->inbound->cmd, rdata,
				   session->inbound->cmdlen);

			// socks5 response
			pgs_evbuffer_add(output, "\x05\x00", 2);
			pgs_evbuffer_add(output, rdata + 2,
					 session->inbound->cmdlen - 2);
			pgs_evbuffer_drain(input, session->inbound->cmdlen);
			session->inbound->state = INBOUND_PROXY;
			return true;
		}
		case 0x02: // TODO: bind
		case 0x03: // TODO: udp associate
		default:
			pgs_session_error(session,
					  "socks5: cmd not supprt yet");
			return false;
		}
	}
	case INBOUND_PROXY: // unreachable
		break;
	default:
		break;
	}

	return false;
}

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
	meta->fin = !!(*data & 0x80);
	meta->opcode = *data & 0x0F;
	meta->mask = !!(*(data + 1) & 0x80);
	meta->payload_len = *(data + 1) & 0x7F;
	meta->header_len = 2 + (meta->mask ? 4 : 0);

	if (meta->payload_len < 126) {
		if (meta->header_len > data_len)
			return false;

	} else if (meta->payload_len == 126) {
		meta->header_len += 2;
		if (meta->header_len > data_len)
			return false;

		meta->payload_len = ntohs(*(uint16_t *)(data + 2));

	} else if (meta->payload_len == 127) {
		meta->header_len += 8;
		if (meta->header_len > data_len)
			return false;

		meta->payload_len = ntohll(*(uint64_t *)(data + 2));
	}

	if (meta->header_len + meta->payload_len > data_len)
		return false;

	const unsigned char *mask_key = data + meta->header_len - 4;

	for (int i = 0; meta->mask && i < meta->payload_len; i++)
		data[meta->header_len + i] ^= mask_key[i % 4];

	return true;
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
	if (!ctx->encryptor) {
		switch (ctx->secure) {
		case V2RAY_SECURE_CFB:
			ctx->encryptor = pgs_aes_cryptor_new(
				EVP_aes_128_cfb(), (const pgs_buf_t *)ctx->key,
				(const pgs_buf_t *)ctx->iv, PGS_ENCRYPT);
			break;
		case V2RAY_SECURE_GCM:
			ctx->encryptor =
				(pgs_base_cryptor_t *)pgs_aead_cryptor_new(
					EVP_aes_128_gcm(),
					(const pgs_buf_t *)ctx->key,
					(const pgs_buf_t *)ctx->iv,
					PGS_ENCRYPT);
			break;
		default:
			// not support yet
			break;
		}
	}

	if (!ctx->decryptor) {
		md5((const pgs_buf_t *)ctx->iv, AES_128_CFB_IV_LEN,
		    (pgs_buf_t *)ctx->riv);
		md5((const pgs_buf_t *)ctx->key, AES_128_CFB_KEY_LEN,
		    (pgs_buf_t *)ctx->rkey);
		switch (ctx->secure) {
		case V2RAY_SECURE_CFB:
			ctx->decryptor = pgs_aes_cryptor_new(
				EVP_aes_128_cfb(), (const pgs_buf_t *)ctx->rkey,
				(const pgs_buf_t *)ctx->riv, PGS_DECRYPT);
			break;
		case V2RAY_SECURE_GCM:
			ctx->decryptor =
				(pgs_base_cryptor_t *)pgs_aead_cryptor_new(
					EVP_aes_128_gcm(),
					(const pgs_buf_t *)ctx->rkey,
					(const pgs_buf_t *)ctx->riv,
					PGS_DECRYPT);
			break;
		default:
			// not support yet
			break;
		}
	}
	offset += AES_128_CFB_IV_LEN;
	// v
	offset += RAND_bytes(header_cmd_raw + offset, 1);
	// standard format data
	header_cmd_raw[offset] = 0x01;
	offset += 1;
	// secure
	header_cmd_raw[offset] = ctx->secure;
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

pgs_size_t pgs_vmess_write_body(const pgs_buf_t *data, pgs_size_t data_len,
				pgs_buf_t *buf, pgs_vmess_ctx_t *ctx)
{
	pgs_buf_t *localr = ctx->local_rbuf;

	assert(data_len + 2 <= _PGS_BUFSIZE);

	switch (ctx->secure) {
	case V2RAY_SECURE_CFB: {
		// L
		localr[0] = (data_len + 4) >> 8;
		localr[1] = (data_len + 4);

		unsigned int f = fnv1a((void *)data, data_len);
		localr[2] = f >> 24;
		localr[3] = f >> 16;
		localr[4] = f >> 8;
		localr[5] = f;

		pgs_memcpy(localr + 6, data, data_len);

		assert(ctx->encryptor != NULL);
		pgs_aes_cryptor_encrypt(ctx->encryptor, localr, data_len + 6,
					buf);
		return data_len + 6;
	}
	case V2RAY_SECURE_GCM: {
		// L
		buf[0] = (data_len + 16) >> 8;
		buf[1] = (data_len + 16);

		assert(ctx->encryptor != NULL);
		int ciphertext_len = 0;
		pgs_aead_cryptor_encrypt((pgs_aead_cryptor_t *)ctx->encryptor,
					 data, data_len, buf + 2 + data_len,
					 buf + 2, &ciphertext_len);

		return ciphertext_len + 16 + 2;
	}
	default:
		// not support yet
		break;
	}

	return 0;
}

bool pgs_vmess_parse(const pgs_buf_t *data, pgs_size_t data_len,
		     pgs_vmess_ctx_t *ctx, pgs_evbuffer_t *writer)
{
	switch (ctx->secure) {
	case V2RAY_SECURE_CFB:
		return pgs_vmess_parse_cfb(data, data_len, ctx, writer);
	case V2RAY_SECURE_GCM:
		return pgs_vmess_parse_gcm(data, data_len, ctx, writer);
	default:
		// not implement yet
		break;
	}
	return false;
}

/* symmetric cipher will eat all the data put in */
bool pgs_vmess_parse_cfb(const pgs_buf_t *data, pgs_size_t data_len,
			 pgs_vmess_ctx_t *ctx, pgs_evbuffer_t *writer)
{
	pgs_vmess_resp_t *meta = &ctx->resp_meta;
	pgs_buf_t *rrbuf = ctx->remote_rbuf;
	pgs_buf_t *lwbuf = ctx->local_wbuf;
	pgs_aes_cryptor_t *decryptor = ctx->decryptor;

	if (!ctx->header_recved) {
		if (data_len < 4)
			return false;
		if (!pgs_aes_cryptor_decrypt(decryptor, data, 4, rrbuf))
			return false;
		meta->v = rrbuf[0];
		meta->opt = rrbuf[1];
		meta->cmd = rrbuf[2];
		meta->m = rrbuf[3];
		if (meta->m != 0) // support no cmd
			return false;
		ctx->header_recved = true;
		ctx->resp_len = 0;
		return pgs_vmess_parse(data + 4, data_len - 4, ctx, writer);
	}

	if (ctx->resp_len == 0) {
		if (data_len == 0) // may called by itself, wait for more data
			return true;
		if (data_len < 2) // illegal data
			return false;
		if (!pgs_aes_cryptor_decrypt(decryptor, data, 2, rrbuf))
			return false;
		int l = rrbuf[0] << 8 | rrbuf[1];

		if (l == 0 || l == 4) // end
			return true;
		if (l < 4)
			return false;
		ctx->resp_len = l - 4;
		ctx->resp_hash = 0;
		// skip fnv1a hash
		return pgs_vmess_parse(data + 2, data_len - 2, ctx, writer);
	}

	if (ctx->resp_hash == 0) {
		if (data_len < 4) // need more data
			return false;
		if (!pgs_aes_cryptor_decrypt(decryptor, data, 4, rrbuf))
			return false;
		ctx->resp_hash = (uint32_t)rrbuf[0] << 24 | rrbuf[1] << 16 |
				 rrbuf[2] << 8 | rrbuf[3];
		return pgs_vmess_parse(data + 4, data_len - 4, ctx, writer);
	}

	if (data_len <= 0) // need more data
		return true;

	pgs_size_t data_to_decrypt =
		ctx->resp_len < data_len ? ctx->resp_len : data_len;
	if (!pgs_aes_cryptor_decrypt(decryptor, data, data_to_decrypt, lwbuf))
		return false;

	pgs_evbuffer_add(writer, lwbuf, data_to_decrypt);
	ctx->resp_len -= data_to_decrypt;

	return pgs_vmess_parse(data + data_to_decrypt,
			       data_len - data_to_decrypt, ctx, writer);
}

/* AEAD cipher */
bool pgs_vmess_parse_gcm(const pgs_buf_t *data, pgs_size_t data_len,
			 pgs_vmess_ctx_t *ctx, pgs_evbuffer_t *writer)
{
	pgs_vmess_resp_t *meta = &ctx->resp_meta;
	pgs_buf_t *rrbuf = ctx->remote_rbuf;
	pgs_buf_t *lwbuf = ctx->local_wbuf;
	pgs_aead_cryptor_t *decryptor = (pgs_aead_cryptor_t *)ctx->decryptor;

	if (!ctx->header_recved) {
		if (data_len < 4)
			return false;
		if (!aes_128_cfb_decrypt(data, 4, (const pgs_buf_t *)ctx->rkey,
					 (const pgs_buf_t *)ctx->riv, rrbuf))
			return false;
		meta->v = rrbuf[0];
		meta->opt = rrbuf[1];
		meta->cmd = rrbuf[2];
		meta->m = rrbuf[3];
		if (meta->m != 0) // support no cmd
			return false;
		ctx->header_recved = true;
		ctx->resp_len = 0;
		return pgs_vmess_parse_gcm(data + 4, data_len - 4, ctx, writer);
	}

	if (ctx->resp_len == 0) {
		if (data_len == 0) // may called by itself, wait for more data
			return true;
		if (data_len < 2) // illegal data
			return false;
		int l = data[0] << 8 | data[1];

		if (l == 0 || l == 16) // end
			return true;
		if (l < 16)
			return false;
		ctx->resp_len = l - 16;
		ctx->resp_hash = -1;
		// skip fnv1a hash
		return pgs_vmess_parse_gcm(data + 2, data_len - 2, ctx, writer);
	}

	if (ctx->remote_rbuf_pos + data_len < ctx->resp_len + 16) {
		// need more data, have to cache this
		pgs_memcpy(rrbuf, data, data_len);
		ctx->remote_rbuf_pos = data_len;
		return true;
	}

	if (ctx->remote_rbuf_pos == 0) {
		// enough data for decoding and no cache
		pgs_size_t data_to_decrypt = ctx->resp_len;
		int decrypt_len = 0;
		if (!pgs_aead_cryptor_decrypt(decryptor, data, ctx->resp_len,
					      data + ctx->resp_len, lwbuf,
					      &decrypt_len))
			return false;

		pgs_evbuffer_add(writer, lwbuf, data_to_decrypt);
		ctx->resp_len -= data_to_decrypt;

		return pgs_vmess_parse_gcm(data + data_to_decrypt + 16,
					   data_len - data_to_decrypt - 16, ctx,
					   writer);
	} else {
		// have some cache in last chunk
		// read more and do the rest
		pgs_size_t data_to_read =
			ctx->resp_len + 16 - ctx->remote_rbuf_pos;
		pgs_memcpy(rrbuf + ctx->remote_rbuf_pos, data, data_to_read);

		int decrypt_len = 0;
		if (!pgs_aead_cryptor_decrypt(decryptor, rrbuf, ctx->resp_len,
					      rrbuf + ctx->resp_len, lwbuf,
					      &decrypt_len))
			return false;

		pgs_evbuffer_add(writer, lwbuf, ctx->resp_len);
		ctx->resp_len = 0;
		ctx->remote_rbuf_pos = 0;

		return pgs_vmess_parse_gcm(data + data_to_read,
					   data_len - data_to_read, ctx,
					   writer);
	}
}
