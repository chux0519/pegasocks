#include "codec/codec.h"
#include "crypto.h"

#include <event2/buffer.h>

static bool shadowsocks_write_local_aes(pgs_session_t *session,
					const uint8_t *msg, size_t len,
					size_t *olen);
static bool shadowsocks_write_local_aead(pgs_session_t *session,
					 const uint8_t *msg, size_t len,
					 size_t *olen);

static void pgs_ss_increase_cryptor_iv(pgs_outbound_ctx_ss_t *ctx,
				       pgs_cryptor_direction_t dir);

bool shadowsocks_write_remote(pgs_session_t *session, const uint8_t *msg,
			      size_t len, size_t *olen)
{
	struct bufferevent *outbev = session->outbound->bev;
	struct evbuffer *outboundw = bufferevent_get_output(outbev);
	pgs_outbound_ctx_ss_t *ssctx = session->outbound->ctx;

	// stream: [iv][chunk]
	// aead chunk: [encrypted payload length(2)][length tag][encrypted payload][payload tag]
	// aes chunk: [encrypted payload]
	// payload: [cmd[3:]][data]
	size_t addr_len = ssctx->cmd_len - 3;
	size_t payload_len = addr_len + len;
	size_t chunk_len, offset, ciphertext_len;
	chunk_len = payload_len;

	const uint8_t *iv = ssctx->enc_iv;
	size_t iv_len = ssctx->iv_len;
	offset = iv_len;

	if (is_aead_cryptor(ssctx->encryptor)) {
		chunk_len = 2 + ssctx->tag_len + payload_len + ssctx->tag_len;
		iv = ssctx->enc_salt;
		iv_len = ssctx->key_len;
		offset = iv_len;

		uint8_t prefix[2] = { 0 };
		prefix[0] = (payload_len & 0x3FFF) >> 8;
		prefix[1] = (payload_len & 0x3FFF);
		//printf("len: %ld, [0]: %d, [1]: %d\n", payload_len, prefix[0],
		//       prefix[1]);
		pgs_cryptor_encrypt(ssctx->encryptor, prefix, 2,
				    ssctx->wbuf + offset + 2 /* tag */,
				    ssctx->wbuf + offset, &ciphertext_len);
		pgs_ss_increase_cryptor_iv(ssctx, PGS_ENCRYPT);
		//debug_hexstring("tag", ssctx->wbuf + offset + 2,
		//		ssctx->tag_len);

		if (ciphertext_len != 2) {
			pgs_session_error(session,
					  "shadowsocks encrypt failed");
			return false;
		}
		offset += (2 + ssctx->tag_len);
	}

	if (ssctx->iv_len + chunk_len > BUFSIZE_16K) {
		pgs_session_error(session, "payload too large");
		return false;
	}

	//debug_hexstring("salt", iv, iv_len);
	//debug_hexstring("key", ssctx->enc_key, ssctx->key_len);
	memcpy(ssctx->wbuf, iv, iv_len);

	uint8_t *payload = malloc(payload_len);
	memcpy(payload, ssctx->cmd + 3, addr_len);
	memcpy(payload + addr_len, msg, len);

	pgs_cryptor_encrypt(ssctx->encryptor, payload, payload_len,
			    ssctx->wbuf + offset + payload_len /* tag */,
			    ssctx->wbuf + offset, &ciphertext_len);
	free(payload);
	pgs_ss_increase_cryptor_iv(ssctx, PGS_ENCRYPT);

	if (ciphertext_len != payload_len) {
		pgs_session_error(session, "shadowsocks encrypt failed");
		return false;
	}

	evbuffer_add(outboundw, ssctx->wbuf, iv_len + chunk_len);

	pgs_session_debug(session, "local -> remote: %d", len);

	*olen = iv_len + chunk_len;
	return true;
}

bool shadowsocks_write_local(pgs_session_t *session, const uint8_t *msg,
			     size_t len, size_t *olen)
{
	if (session->inbound->state != INBOUND_PROXY)
		return false;

	pgs_outbound_ctx_ss_t *ssctx = session->outbound->ctx;
	if (is_aead_cipher(ssctx->cipher)) {
		return shadowsocks_write_local_aead(session, msg, len, olen);
	} else {
		return shadowsocks_write_local_aes(session, msg, len, olen);
	}
}

// static
static void pgs_ss_increase_cryptor_iv(pgs_outbound_ctx_ss_t *ctx,
				       pgs_cryptor_direction_t dir)
{
	if (is_aead_cipher(ctx->cipher)) {
		pgs_cryptor_t *cryptor = NULL;
		uint8_t *iv = NULL;
		switch (dir) {
		case PGS_DECRYPT:
			cryptor = ctx->decryptor;
			iv = ctx->dec_iv;
			break;
		case PGS_ENCRYPT:
			cryptor = ctx->encryptor;
			iv = ctx->enc_iv;
			break;
		default:
			break;
		}

		if (iv != NULL && cryptor != NULL) {
			pgs_increase_nonce(iv, ctx->iv_len);
			pgs_cryptor_reset_iv(cryptor, iv);
		}
	}
}

static bool shadowsocks_write_local_aes(pgs_session_t *session,
					const uint8_t *msg, size_t len,
					size_t *olen)
{
	pgs_outbound_ctx_ss_t *ssctx = session->outbound->ctx;
	return true;
}

static bool shadowsocks_write_local_aead(pgs_session_t *session,
					 const uint8_t *msg, size_t len,
					 size_t *olen)
{
	struct bufferevent *inbev = session->inbound->bev;
	struct evbuffer *inboundw = bufferevent_get_output(inbev);

	pgs_outbound_ctx_ss_t *ssctx = session->outbound->ctx;
	size_t offset = 0;
	size_t decode_len, plen;
	while (len > 0) {
		if (!ssctx->decryptor) {
			if (len < ssctx->key_len) {
				// need more data
				return true;
			}
			hkdf_sha1(msg /*salt*/, ssctx->key_len, ssctx->ikm,
				  ssctx->key_len, (const uint8_t *)SS_INFO, 9,
				  ssctx->dec_key, ssctx->key_len);
			ssctx->decryptor =
				pgs_cryptor_new(ssctx->cipher, PGS_DECRYPT,
						ssctx->dec_key, ssctx->dec_iv);
			*olen += ssctx->key_len;
			len -= ssctx->key_len;
			offset += ssctx->key_len;
		}
		assert(ssctx->decryptor);
		if (len < 2 + ssctx->tag_len) {
			// need more data
			return true;
		}
		// chunk
		uint8_t chunk_len[2];
		pgs_cryptor_decrypt(ssctx->decryptor, msg + offset, 2,
				    msg + offset + 2, chunk_len, &decode_len);
		if (decode_len != 2) {
			return false;
		}
		offset += (2 + ssctx->tag_len);
		*olen += (2 + ssctx->tag_len);
		len -= (2 + ssctx->tag_len);
		plen = (chunk_len[0] << 8) | chunk_len[1];
		if (len < plen + ssctx->tag_len) {
			*olen -=
				(2 +
				 ssctx->tag_len); /* will decode the length again */
			return true;
		}
		pgs_ss_increase_cryptor_iv(ssctx, PGS_DECRYPT);

		pgs_cryptor_decrypt(ssctx->decryptor, msg + offset, plen,
				    msg + offset + plen, ssctx->rbuf,
				    &decode_len);
		if (decode_len != plen) {
			return false;
		}
		pgs_ss_increase_cryptor_iv(ssctx, PGS_DECRYPT);
		evbuffer_add(inboundw, ssctx->rbuf, plen);
		offset += (plen + ssctx->tag_len);
		*olen += (plen + ssctx->tag_len);
		len -= (plen + ssctx->tag_len);
		printf("decoded chunk\n");
	}

	return true;
}
