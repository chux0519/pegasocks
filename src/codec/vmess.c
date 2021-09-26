#include "codec/codec.h"
#include "crypto.h"

#include <assert.h>

#include <event2/buffer.h>

const char vmess_key_suffix[36] = "c48619fe-8f02-49e0-b9e9-edf763e17e21";

static size_t pgs_vmess_write_head(pgs_session_t *session,
				   pgs_outbound_ctx_v2ray_t *ctx);
static size_t pgs_vmess_write_body(pgs_session_t *session, const uint8_t *data,
				   size_t data_len, size_t head_len,
				   pgs_session_write_fn flush);
static bool vmess_write_local_cfb(pgs_session_t *session, const uint8_t *data,
				  size_t data_len, size_t *olen,
				  pgs_session_write_fn flush);
static bool vmess_write_local_aead(pgs_session_t *session, const uint8_t *data,
				   size_t data_len, size_t *olen,
				   pgs_session_write_fn flush);

static void pgs_vmess_init_encryptor(pgs_outbound_ctx_v2ray_t *ctx);
static void pgs_vmess_init_decryptor(pgs_outbound_ctx_v2ray_t *ctx);
static void pgs_vmess_increase_cryptor_iv(pgs_outbound_ctx_v2ray_t *ctx,
					  pgs_cryptor_direction_t dir);
static void vmess_flush_remote(pgs_session_t *session, uint8_t *data,
			       size_t len);
static void vmess_flush_local(pgs_session_t *session, uint8_t *data,
			      size_t len);

bool vmess_write_remote(pgs_session_t *session, const uint8_t *data,
			size_t data_len, size_t *olen)
{
	pgs_outbound_ctx_v2ray_t *ctx = session->outbound->ctx;
	size_t head_len = 0;
	if (!ctx->header_sent) {
		// will setup crytors and remote_wbuf
		head_len = pgs_vmess_write_head(session, ctx);
		ctx->header_sent = true;
	}

	size_t body_len = pgs_vmess_write_body(session, data, data_len,
					       head_len, vmess_flush_remote);
	*olen = body_len + head_len;
	return true;
}

bool vmess_write_local(pgs_session_t *session, const uint8_t *data,
		       size_t data_len, size_t *olen)
{
	pgs_outbound_ctx_v2ray_t *ctx = session->outbound->ctx;
	switch (ctx->cipher) {
	case AES_128_CFB:
		return vmess_write_local_cfb(session, data, data_len, olen,
					     vmess_flush_local);
	case AEAD_AES_128_GCM:
	case AEAD_CHACHA20_POLY1305:
		return vmess_write_local_aead(session, data, data_len, olen,
					      vmess_flush_local);
	default:
		// not implement yet
		break;
	}
	return false;
}

// static functions

static void pgs_vmess_init_encryptor(pgs_outbound_ctx_v2ray_t *ctx)
{
	switch (ctx->cipher) {
	case AES_128_CFB:
		ctx->encryptor = pgs_cryptor_new(ctx->cipher, PGS_ENCRYPT,
						 (const uint8_t *)ctx->key,
						 (const uint8_t *)ctx->iv);
		break;
	case AEAD_AES_128_GCM:
		assert(ctx->iv_len == AEAD_AES_128_GCM_IV_LEN);
		assert(ctx->key_len == AEAD_AES_128_GCM_KEY_LEN);
		memcpy(ctx->data_enc_key, ctx->key, AEAD_AES_128_GCM_KEY_LEN);
		memcpy(ctx->data_enc_iv + 2, ctx->iv + 2, 10);
		ctx->encryptor =
			pgs_cryptor_new(ctx->cipher, PGS_ENCRYPT,
					(const uint8_t *)ctx->data_enc_key,
					(const uint8_t *)ctx->data_enc_iv);
		break;
	case AEAD_CHACHA20_POLY1305:
		assert(ctx->iv_len == AEAD_CHACHA20_POLY1305_IV_LEN);
		assert(ctx->key_len == AEAD_CHACHA20_POLY1305_KEY_LEN);
		md5((const uint8_t *)ctx->key, AES_128_CFB_IV_LEN,
		    ctx->data_enc_key);
		md5(ctx->data_enc_key, MD5_LEN, ctx->data_enc_key + MD5_LEN);
		memcpy(ctx->data_enc_iv + 2, ctx->iv + 2, 10);
		ctx->encryptor =
			pgs_cryptor_new(ctx->cipher, PGS_ENCRYPT,
					(const uint8_t *)ctx->data_enc_key,
					(const uint8_t *)ctx->data_enc_iv);
		break;
	case AEAD_AES_256_GCM:
		// not supported
	default:
		break;
	}
}

static void pgs_vmess_init_decryptor(pgs_outbound_ctx_v2ray_t *ctx)
{
	// riv rkey to decode header
	md5((const uint8_t *)ctx->iv, AES_128_CFB_IV_LEN, (uint8_t *)ctx->riv);
	md5((const uint8_t *)ctx->key, AES_128_CFB_KEY_LEN,
	    (uint8_t *)ctx->rkey);
	switch (ctx->cipher) {
	case AES_128_CFB:
		ctx->decryptor = pgs_cryptor_new(ctx->cipher, PGS_DECRYPT,
						 (const uint8_t *)ctx->rkey,
						 (const uint8_t *)ctx->riv);
		break;
	case AEAD_AES_128_GCM:
		assert(ctx->iv_len == AEAD_AES_128_GCM_IV_LEN);
		assert(ctx->key_len == AEAD_AES_128_GCM_KEY_LEN);
		memcpy(ctx->data_dec_key, ctx->rkey, AEAD_AES_128_GCM_KEY_LEN);
		ctx->dec_counter = 0;
		memcpy(ctx->data_dec_iv + 2, ctx->riv + 2, 10);
		ctx->decryptor =
			pgs_cryptor_new(ctx->cipher, PGS_DECRYPT,
					(const uint8_t *)ctx->data_dec_key,
					(const uint8_t *)ctx->data_dec_iv);
		break;
	case AEAD_CHACHA20_POLY1305:
		assert(ctx->iv_len == AEAD_CHACHA20_POLY1305_IV_LEN);
		assert(ctx->key_len == AEAD_CHACHA20_POLY1305_KEY_LEN);
		md5((const uint8_t *)ctx->rkey, AES_128_CFB_IV_LEN,
		    ctx->data_dec_key);
		md5(ctx->data_dec_key, MD5_LEN, ctx->data_dec_key + MD5_LEN);
		ctx->dec_counter = 0;
		memcpy(ctx->data_dec_iv + 2, ctx->riv + 2, 10);
		ctx->decryptor =
			pgs_cryptor_new(ctx->cipher, PGS_DECRYPT,
					(const uint8_t *)ctx->data_dec_key,
					(const uint8_t *)ctx->data_dec_iv);
		break;
	case AEAD_AES_256_GCM:
		// not supported
	default:
		break;
	}
}

static void pgs_vmess_increase_cryptor_iv(pgs_outbound_ctx_v2ray_t *ctx,
					  pgs_cryptor_direction_t dir)
{
	if (ctx->cipher == AES_128_CFB)
		return;

	uint16_t *counter = NULL;
	pgs_cryptor_t *cryptor = NULL;
	uint8_t *iv = NULL;
	switch (dir) {
	case PGS_DECRYPT:
		counter = &ctx->dec_counter;
		cryptor = ctx->decryptor;
		iv = ctx->data_dec_iv;
		break;
	case PGS_ENCRYPT:
		counter = &ctx->enc_counter;
		cryptor = ctx->encryptor;
		iv = ctx->data_enc_iv;
		break;
	default:
		break;
	}

	if (counter != NULL && cryptor != NULL) {
		*counter += 1;
		iv[0] = *counter >> 8;
		iv[1] = *counter;

		pgs_cryptor_reset_iv(cryptor, iv);
	}
}

static void vmess_flush_remote(pgs_session_t *session, uint8_t *data,
			       size_t len)
{
	struct bufferevent *outbev = session->outbound->bev;
	struct evbuffer *outboundw = bufferevent_get_output(outbev);
	const pgs_server_config_t *config = session->outbound->config;
	const pgs_config_extra_v2ray_t *vconfig = config->extra;
	if (vconfig->websocket.enabled) {
		pgs_ws_write_bin(outboundw, data, len);
	} else {
		evbuffer_add(outboundw, data, len);
	}
}

static void vmess_flush_local(pgs_session_t *session, uint8_t *data, size_t len)
{
	struct bufferevent *inbev = session->inbound->bev;
	struct evbuffer *inboundw = bufferevent_get_output(inbev);
	uint8_t *udp_packet = NULL;
	if (session->inbound->state == INBOUND_PROXY) {
		// TCP
		evbuffer_add(inboundw, data, len);
	} else if (session->inbound->state == INBOUND_UDP_RELAY &&
		   session->inbound->udp_fd != -1) {
		// pack to socks5 packet
		pgs_outbound_ctx_v2ray_t *ctx = session->outbound->ctx;
		size_t udp_packet_len = 2 + 1 + ctx->target_addr_len + len;
		udp_packet = malloc(udp_packet_len);
		if (udp_packet == NULL) {
			pgs_session_error(session, "out of memory");
			return;
		}
		udp_packet[0] = 0x00;
		udp_packet[1] = 0x00;
		udp_packet[2] = 0x00;
		memcpy(udp_packet + 3, ctx->target_addr, ctx->target_addr_len);
		memcpy(udp_packet + 3 + ctx->target_addr_len, data, len);
		int n = sendto(
			session->inbound->udp_fd, udp_packet, udp_packet_len, 0,
			(struct sockaddr *)&session->inbound->udp_client_addr,
			session->inbound->udp_client_addr_size);
		pgs_session_debug(session, "write %d bytes to local udp sock",
				  n);
		free(udp_packet);
	}
}

/* symmetric cipher will eat all the data put in */
static bool vmess_write_local_cfb(pgs_session_t *session, const uint8_t *data,
				  size_t data_len, size_t *olen,
				  pgs_session_write_fn flush)
{
	pgs_outbound_ctx_v2ray_t *ctx = session->outbound->ctx;
	pgs_vmess_resp_t meta = { 0 };
	uint8_t *rrbuf = ctx->remote_rbuf;
	uint8_t *lwbuf = ctx->local_wbuf;
	pgs_cryptor_t *decryptor = ctx->decryptor;

	size_t decrypt_len = 0;
	if (!ctx->header_recved) {
		if (data_len < 4)
			return false;
		if (!pgs_cryptor_decrypt(decryptor, data, 4, NULL, rrbuf,
					 &decrypt_len))
			return false;
		meta.v = rrbuf[0];
		meta.opt = rrbuf[1];
		meta.cmd = rrbuf[2];
		meta.m = rrbuf[3];
		if (meta.v != ctx->v)
			return false;
		if (meta.m != 0) // support no cmd
			return false;
		ctx->header_recved = true;
		ctx->resp_len = 0;
		return vmess_write_local_cfb(session, data + 4, data_len - 4,
					     olen, flush);
	}

	if (ctx->resp_len == 0) {
		if (data_len == 0) // may called by itself, wait for more data
			return true;
		if (data_len < 2) // illegal data
			return false;
		if (!pgs_cryptor_decrypt(decryptor, data, 2, NULL, rrbuf,
					 &decrypt_len))
			return false;

		int l = rrbuf[0] << 8 | rrbuf[1];

		if (l == 0 || l == 4) // end
			return true;
		if (l < 4)
			return false;
		ctx->resp_len = l - 4;
		ctx->resp_hash = 0;
		// skip fnv1a hash
		return vmess_write_local_cfb(session, data + 2, data_len - 2,
					     olen, flush);
	}

	if (ctx->resp_hash == 0) {
		if (data_len < 4) // need more data
			return false;
		if (!pgs_cryptor_decrypt(decryptor, data, 4, NULL, rrbuf,
					 &decrypt_len))
			return false;
		ctx->resp_hash = (uint32_t)rrbuf[0] << 24 | rrbuf[1] << 16 |
				 rrbuf[2] << 8 | rrbuf[3];
		return vmess_write_local_cfb(session, data + 4, data_len - 4,
					     olen, flush);
	}

	if (data_len <= 0) // need more data
		return true;

	size_t data_to_decrypt =
		ctx->resp_len < data_len ? ctx->resp_len : data_len;
	if (!pgs_cryptor_decrypt(decryptor, data, data_to_decrypt, NULL, lwbuf,
				 &decrypt_len))
		return false;

	flush(session, lwbuf, data_to_decrypt);
	*olen += data_len;
	ctx->resp_len -= data_to_decrypt;

	return vmess_write_local_cfb(session, data + data_to_decrypt,
				     data_len - data_to_decrypt, olen, flush);
}

/* AEAD cipher */
static bool vmess_write_local_aead(pgs_session_t *session, const uint8_t *data,
				   size_t data_len, size_t *olen,
				   pgs_session_write_fn flush)
{
	pgs_outbound_ctx_v2ray_t *ctx = session->outbound->ctx;
	pgs_vmess_resp_t meta = { 0 };
	uint8_t *rrbuf = ctx->remote_rbuf;
	uint8_t *lwbuf = ctx->local_wbuf;
	pgs_cryptor_t *decryptor = ctx->decryptor;

	if (!ctx->header_recved) {
		if (data_len < 4)
			return false;
		if (!aes_128_cfb_decrypt(data, 4, (const uint8_t *)ctx->rkey,
					 (const uint8_t *)ctx->riv, rrbuf))
			return false;
		meta.v = rrbuf[0];
		meta.opt = rrbuf[1];
		meta.cmd = rrbuf[2];
		meta.m = rrbuf[3];
		if (meta.v != ctx->v)
			return false;
		if (meta.m != 0) // support no cmd
			return false;
		ctx->header_recved = true;
		ctx->resp_len = 0;
		return vmess_write_local_aead(session, data + 4, data_len - 4,
					      olen, flush);
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
		return vmess_write_local_aead(session, data + 2, data_len - 2,
					      olen, flush);
	}

	if (ctx->remote_rbuf_pos + data_len < ctx->resp_len + 16) {
		// need more data, have to cache this
		memcpy(rrbuf + ctx->remote_rbuf_pos, data, data_len);
		ctx->remote_rbuf_pos += data_len;
		return true;
	}

	size_t decrypt_len = 0;
	if (ctx->remote_rbuf_pos == 0) {
		// enough data for decoding and no cache
		size_t data_to_decrypt = ctx->resp_len;
		bool ok = pgs_cryptor_decrypt(decryptor, data, ctx->resp_len,
					      data + ctx->resp_len, lwbuf,
					      &decrypt_len);
		pgs_vmess_increase_cryptor_iv(ctx, PGS_DECRYPT);
		if (!ok)
			return false;

		flush(session, lwbuf, data_to_decrypt);
		*olen += data_to_decrypt;
		ctx->resp_len -= data_to_decrypt;

		return vmess_write_local_aead(session,
					      data + data_to_decrypt + 16,
					      data_len - data_to_decrypt - 16,
					      olen, flush);
	} else {
		// have some cache in last chunk
		// read more and do the rest
		size_t data_to_read = ctx->resp_len + 16 - ctx->remote_rbuf_pos;
		memcpy(rrbuf + ctx->remote_rbuf_pos, data, data_to_read);

		bool ok = pgs_cryptor_decrypt(decryptor, rrbuf, ctx->resp_len,
					      rrbuf + ctx->resp_len, lwbuf,
					      &decrypt_len);
		pgs_vmess_increase_cryptor_iv(ctx, PGS_DECRYPT);
		if (!ok)
			return false;
		flush(session, lwbuf, ctx->resp_len);
		*olen += ctx->resp_len;
		ctx->resp_len = 0;
		ctx->remote_rbuf_pos = 0;

		return vmess_write_local_aead(session, data + data_to_read,
					      data_len - data_to_read, olen,
					      flush);
	}
}

static size_t pgs_vmess_write_head(pgs_session_t *session,
				   pgs_outbound_ctx_v2ray_t *ctx)
{
	const uint8_t *uuid = session->outbound->config->password;
	int is_udp = (session->inbound != NULL &&
		      session->inbound->state == INBOUND_UDP_RELAY);
	const uint8_t *udp_rbuf = NULL;
	if (is_udp) {
		udp_rbuf = session->inbound->udp_rbuf;
	}

	uint8_t *buf = ctx->remote_wbuf;
	const uint8_t *socks5_cmd = ctx->cmd;
	size_t socks5_cmd_len = ctx->cmdlen;

	// auth part
	time_t now = time(NULL);
	unsigned long ts = htonll(now);
	uint8_t header_auth[MD5_LEN];
	size_t header_auth_len = 0;
	hmac_md5(uuid, 16, (const uint8_t *)&ts, 8, header_auth,
		 &header_auth_len);
	assert(header_auth_len == MD5_LEN);
	memcpy(buf, header_auth, header_auth_len);

	// command part
	int n = socks5_cmd_len - 4 - 2;
	if (is_udp) {
		n = pgs_get_addr_len(udp_rbuf + 3);
	}
	int p = 0;
	size_t header_cmd_len =
		1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + n + p + 4;
	uint8_t header_cmd_raw[header_cmd_len];
	uint8_t header_cmd_encoded[header_cmd_len];
	memzero(header_cmd_raw, header_cmd_len);
	memzero(header_cmd_encoded, header_cmd_len);

	int offset = 0;
	// ver
	header_cmd_raw[0] = 1;
	offset += 1;
	// data iv
	rand_bytes(header_cmd_raw + offset, AES_128_CFB_IV_LEN);
	memcpy(ctx->iv, header_cmd_raw + offset, AES_128_CFB_IV_LEN);
	offset += AES_128_CFB_IV_LEN;
	// data key
	rand_bytes(header_cmd_raw + offset, AES_128_CFB_KEY_LEN);
	memcpy(ctx->key, header_cmd_raw + offset, AES_128_CFB_KEY_LEN);
	offset += AES_128_CFB_KEY_LEN;

	// init data encryptor
	if (!ctx->encryptor)
		pgs_vmess_init_encryptor(ctx);
	assert(ctx->encryptor != NULL);

	if (!ctx->decryptor)
		pgs_vmess_init_decryptor(ctx);
	assert(ctx->decryptor != NULL);

	// v
	rand_bytes(header_cmd_raw + offset, 1);
	ctx->v = header_cmd_raw[offset];
	offset += 1;
	// standard format data
	header_cmd_raw[offset] = 0x01;
	offset += 1;
	// secure
	header_cmd_raw[offset] = ctx->cipher;
	offset += 1;
	// X
	header_cmd_raw[offset] = 0x00;
	offset += 1;

	if (is_udp) {
		header_cmd_raw[offset] = 0x02;
	} else {
		header_cmd_raw[offset] = 0x01;
	}
	offset += 1;

	if (is_udp) {
		// port
		header_cmd_raw[offset] = udp_rbuf[4 + n];
		header_cmd_raw[offset + 1] = udp_rbuf[4 + n + 1];
		offset += 2;
		// atype
		if (udp_rbuf[3] == 0x01) {
			header_cmd_raw[offset] = 0x01;
		} else {
			header_cmd_raw[offset] = udp_rbuf[3] - 1;
		}
		offset += 1;
		// addr
		memcpy(header_cmd_raw + offset, udp_rbuf + 4, n);
		offset += n;
	} else {
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
		memcpy(header_cmd_raw + offset, socks5_cmd + 4, n);
		offset += n;
	}

	assert(offset + 4 == header_cmd_len);

	unsigned int f = fnv1a(header_cmd_raw, header_cmd_len - 4);

	header_cmd_raw[offset] = f >> 24;
	header_cmd_raw[offset + 1] = f >> 16;
	header_cmd_raw[offset + 2] = f >> 8;
	header_cmd_raw[offset + 3] = f;

	uint8_t k_md5_input[16 + 36];
	memcpy(k_md5_input, uuid, 16);
	memcpy(k_md5_input + 16, vmess_key_suffix, 36);
	uint8_t cmd_k[AES_128_CFB_KEY_LEN];
	md5(k_md5_input, 16 + 36, cmd_k);

	uint8_t iv_md5_input[32];
	now = time(NULL);
	ts = htonll(now);
	memcpy(iv_md5_input, (const unsigned char *)&ts, 8);
	memcpy(iv_md5_input + 8, (const unsigned char *)&ts, 8);
	memcpy(iv_md5_input + 16, (const unsigned char *)&ts, 8);
	memcpy(iv_md5_input + 24, (const unsigned char *)&ts, 8);
	uint8_t cmd_iv[AES_128_CFB_IV_LEN];
	md5(iv_md5_input, 32, cmd_iv);

	aes_128_cfb_encrypt(header_cmd_raw, header_cmd_len, cmd_k, cmd_iv,
			    header_cmd_encoded);
	memcpy(buf + header_auth_len, header_cmd_encoded, header_cmd_len);

	return header_auth_len + header_cmd_len;
}

static size_t pgs_vmess_write_body(pgs_session_t *session, const uint8_t *data,
				   size_t data_len, size_t head_len,
				   pgs_session_write_fn flush)
{
	pgs_outbound_ctx_v2ray_t *ctx = session->outbound->ctx;
	uint8_t *localr = ctx->local_rbuf;
	uint8_t *buf = ctx->remote_wbuf + head_len;
	size_t sent = 0;
	size_t offset = 0;
	size_t remains = data_len;
	size_t frame_data_len = data_len;

	while (remains > 0) {
		buf = ctx->remote_wbuf + head_len;
		switch (ctx->cipher) {
		case AES_128_CFB: {
			if (remains + 6 > BUFSIZE_16K - head_len) {
				frame_data_len = BUFSIZE_16K - head_len - 6;
			} else {
				frame_data_len = remains;
			}
			// L
			localr[0] = (frame_data_len + 4) >> 8;
			localr[1] = (frame_data_len + 4);

			unsigned int f =
				fnv1a((void *)data + offset, frame_data_len);
			localr[2] = f >> 24;
			localr[3] = f >> 16;
			localr[4] = f >> 8;
			localr[5] = f;

			memcpy(localr + 6, data + offset, frame_data_len);

			size_t ciphertext_len = 0;
			pgs_cryptor_encrypt(ctx->encryptor, localr,
					    frame_data_len + 6, NULL, buf,
					    &ciphertext_len);
			sent += (frame_data_len + 6);
			flush(session, ctx->remote_wbuf,
			      head_len + frame_data_len + 6);
			break;
		}
		case AEAD_AES_128_GCM:
		case AEAD_CHACHA20_POLY1305: {
			if (remains + 18 > BUFSIZE_16K - head_len) {
				// more than one frame
				frame_data_len = BUFSIZE_16K - head_len - 18;
			} else {
				frame_data_len = remains;
			}
			// L
			buf[0] = (frame_data_len + 16) >> 8;
			buf[1] = (frame_data_len + 16);

			size_t ciphertext_len = 0;
			bool ok = pgs_cryptor_encrypt(ctx->encryptor,
						      data + offset,
						      frame_data_len,
						      buf + 2 + frame_data_len,
						      buf + 2, &ciphertext_len);
			pgs_vmess_increase_cryptor_iv(ctx, PGS_ENCRYPT);

			assert(ciphertext_len == frame_data_len);
			sent += (frame_data_len + 18);
			flush(session, ctx->remote_wbuf,
			      head_len + frame_data_len + 18);
			break;
		}
		default:
			// not support yet
			break;
		}

		offset += frame_data_len;
		remains -= frame_data_len;
		if (head_len > 0)
			head_len = 0;
	}

	return sent;
}
