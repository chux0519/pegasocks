#include "codec/codec.h"
#include "crypto.h"

#include <event2/buffer.h>

static bool shadowsocks_write_local_aes(pgs_session_t *session,
					const uint8_t *msg, size_t len,
					size_t *olen, size_t *clen);
static bool shadowsocks_write_local_aead(pgs_session_t *session,
					 const uint8_t *msg, size_t len,
					 size_t *olen, size_t *clen);

static bool shadowsocks_write_remote_aes(pgs_session_t *session,
					 const uint8_t *msg, size_t len,
					 size_t *olen);
static bool shadowsocks_write_remote_aead(pgs_session_t *session,
					  const uint8_t *msg, size_t len,
					  size_t *olen);

static void pgs_ss_increase_cryptor_iv(pgs_outbound_ctx_ss_t *ctx,
				       pgs_cryptor_direction_t dir);

bool shadowsocks_write_remote(pgs_session_t *session, const uint8_t *msg,
			      size_t len, size_t *olen)
{
	pgs_outbound_ctx_ss_t *ssctx = session->outbound->ctx;

	if (is_aead_cipher(ssctx->cipher)) {
		return shadowsocks_write_remote_aead(session, msg, len, olen);
	} else {
		return shadowsocks_write_remote_aes(session, msg, len, olen);
	}
}

bool shadowsocks_write_local(pgs_session_t *session, const uint8_t *msg,
			     size_t len, size_t *olen,
			     size_t *clen /* consumed len */)
{
	pgs_outbound_ctx_ss_t *ssctx = session->outbound->ctx;
	if (is_aead_cipher(ssctx->cipher)) {
		return shadowsocks_write_local_aead(session, msg, len, olen,
						    clen);
	} else {
		return shadowsocks_write_local_aes(session, msg, len, olen,
						   clen);
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
					size_t *olen, size_t *clen)
{
	struct bufferevent *inbev = session->inbound->bev;
	struct evbuffer *inboundw = bufferevent_get_output(inbev);

	pgs_outbound_ctx_ss_t *ssctx = session->outbound->ctx;

	size_t offset = 0, decode_len = 0;
	if (ssctx->decryptor == NULL) {
		if (len < ssctx->iv_len) {
			pgs_session_error(session, "need data for iv");
			return false;
		}
		memcpy(ssctx->dec_iv, msg, ssctx->iv_len);
		memcpy(ssctx->dec_key, ssctx->ikm, ssctx->key_len);
		ssctx->decryptor =
			pgs_cryptor_new(ssctx->cipher, PGS_DECRYPT,
					ssctx->dec_key, ssctx->dec_iv);
		offset += ssctx->iv_len;
	}
	assert(ssctx->decryptor != NULL);

	size_t mlen = len - offset;
	bool ok = pgs_cryptor_decrypt(ssctx->decryptor, msg + offset, mlen,
				      NULL, ssctx->rbuf, &decode_len);
	if (!ok || decode_len != mlen) {
		return false;
	}
	evbuffer_add(inboundw, ssctx->rbuf, mlen);
	*olen = mlen;
	*clen = len;
	return true;
}

static bool shadowsocks_write_local_aead(pgs_session_t *session,
					 const uint8_t *msg, size_t len,
					 size_t *olen, size_t *clen)
{
	struct bufferevent *inbev = session->inbound->bev;
	struct evbuffer *inboundw = bufferevent_get_output(inbev);

	pgs_outbound_ctx_ss_t *ssctx = session->outbound->ctx;
	*clen = 0;
	size_t decode_len;

	// init decryptor
	if (!ssctx->decryptor) {
		if (len < ssctx->key_len) {
			pgs_session_error(session,
					  "need atl least %ld bytes for salt",
					  ssctx->key_len);
			return false;
		}
		hkdf_sha1(msg /*salt*/, ssctx->key_len, ssctx->ikm,
			  ssctx->key_len, (const uint8_t *)SS_INFO, 9,
			  ssctx->dec_key, ssctx->key_len);
		ssctx->decryptor =
			pgs_cryptor_new(ssctx->cipher, PGS_DECRYPT,
					ssctx->dec_key, ssctx->dec_iv);
		*clen += ssctx->key_len;
		len -= ssctx->key_len;
	}
	assert(ssctx->decryptor);

	int last_state = ssctx->aead_decode_state;
	while (true) {
		switch (ssctx->aead_decode_state) {
		case READY: {
			if (ssctx->plen == 0) {
				// parse plen
				if (len < 2 + ssctx->tag_len) {
					ssctx->aead_decode_state =
						WAIT_MORE_FOR_LEN;
					pgs_session_debug(
						session,
						"need more data for payload len");
					return true;
				}
				uint8_t chunk_len[2];
				pgs_cryptor_decrypt(ssctx->decryptor,
						    msg + *clen, 2,
						    msg + *clen + 2, chunk_len,
						    &decode_len);
				pgs_ss_increase_cryptor_iv(ssctx, PGS_DECRYPT);
				if (decode_len != 2) {
					return false;
				}
				*clen += (2 + ssctx->tag_len);
				len -= (2 + ssctx->tag_len);
				ssctx->plen = (uint16_t)chunk_len[0] << 8 |
					      chunk_len[1];
			} else {
				// parse payload
				if (len < ssctx->plen + ssctx->tag_len) {
					ssctx->aead_decode_state =
						WAIT_MORE_FOR_PAYLOAD;
					pgs_session_debug(
						session,
						"need more data for payload");
					return true;
				}
				pgs_cryptor_decrypt(ssctx->decryptor,
						    msg + *clen, ssctx->plen,
						    msg + *clen + ssctx->plen,
						    ssctx->rbuf, &decode_len);
				pgs_ss_increase_cryptor_iv(ssctx, PGS_DECRYPT);
				if (decode_len != ssctx->plen) {
					return false;
				}
				evbuffer_add(inboundw, ssctx->rbuf,
					     ssctx->plen);
				*olen += ssctx->plen;
				*clen += (ssctx->plen + ssctx->tag_len);
				len -= (ssctx->plen + ssctx->tag_len);
				ssctx->plen = 0;
			}
			break;
		}
		case WAIT_MORE_FOR_LEN: {
			if (len < 2 + ssctx->tag_len) {
				pgs_session_debug(
					session,
					"need more data for payload len");
				return true;
			}
			ssctx->aead_decode_state = READY;
			break;
		}
		case WAIT_MORE_FOR_PAYLOAD: {
			if (len < ssctx->plen + ssctx->tag_len) {
				pgs_session_debug(session,
						  "need more data for payload");
				return true;
			}
			ssctx->aead_decode_state = READY;
			break;
		}
		}
	}
}

static bool shadowsocks_write_remote_aes(pgs_session_t *session,
					 const uint8_t *msg, size_t len,
					 size_t *olen)
{
	struct bufferevent *outbev = session->outbound->bev;
	struct evbuffer *outboundw = bufferevent_get_output(outbev);
	pgs_outbound_ctx_ss_t *ssctx = session->outbound->ctx;

	// stream: [iv][chunk]
	// aes chunk: [encrypted payload]
	// first chunk [cmd[3:]][data]
	size_t ciphertext_len;

	if (!ssctx->iv_sent) {
		const uint8_t *iv = ssctx->enc_iv;
		size_t iv_len = ssctx->iv_len;

		memcpy(ssctx->wbuf, iv, iv_len);
		ssctx->iv_sent = true;

		size_t addr_len = ssctx->cmd_len - 3;
		size_t chunk_len = addr_len + len;
		if (iv_len + chunk_len > BUFSIZE_16K) {
			pgs_session_error(session, "payload too large");
			return false;
		}
		uint8_t *payload = malloc(chunk_len);
		memcpy(payload, ssctx->cmd + 3, addr_len);
		memcpy(payload + addr_len, msg, len);

		bool ok = pgs_cryptor_encrypt(ssctx->encryptor, payload,
					      chunk_len, NULL,
					      ssctx->wbuf + iv_len,
					      &ciphertext_len);
		free(payload);

		if (!ok || ciphertext_len != chunk_len) {
			pgs_session_error(session,
					  "shadowsocks encrypt failed");
			return false;
		}

		*olen = iv_len + chunk_len;
	} else {
		bool ok = pgs_cryptor_encrypt(ssctx->encryptor, msg, len, NULL,
					      ssctx->wbuf, &ciphertext_len);
		if (!ok || ciphertext_len != len) {
			pgs_session_error(session,
					  "shadowsocks encrypt failed");
			return false;
		}
		*olen = len;
	}
	evbuffer_add(outboundw, ssctx->wbuf, *olen);
	return true;
}

static bool shadowsocks_write_remote_aead(pgs_session_t *session,
					  const uint8_t *msg, size_t len,
					  size_t *olen)
{
	struct bufferevent *outbev = session->outbound->bev;
	struct evbuffer *outboundw = bufferevent_get_output(outbev);
	pgs_outbound_ctx_ss_t *ssctx = session->outbound->ctx;

	// stream: [iv][chunk]
	// aead chunk: [encrypted payload length(2)][length tag][encrypted payload][payload tag]
	// first chunk: [cmd[3:]][data]
	size_t addr_len = ssctx->cmd_len - 3;
	size_t payload_len = len;
	size_t chunk_len = 2 + ssctx->tag_len + payload_len + ssctx->tag_len;

	size_t offset = 0;

	if (!ssctx->iv_sent) {
		const uint8_t *salt = ssctx->enc_salt;
		size_t salt_len = ssctx->key_len;
		memcpy(ssctx->wbuf, salt, salt_len);

		offset += salt_len;
		payload_len = len + addr_len;
	}

	if (payload_len > 0x3FFF) {
		return false;
	}

	uint8_t prefix[2] = { 0 };
	prefix[0] = payload_len >> 8;
	prefix[1] = payload_len;

	size_t ciphertext_len;
	pgs_cryptor_encrypt(ssctx->encryptor, prefix, 2,
			    ssctx->wbuf + offset + 2 /* tag */,
			    ssctx->wbuf + offset, &ciphertext_len);
	pgs_ss_increase_cryptor_iv(ssctx, PGS_ENCRYPT);

	if (ciphertext_len != 2) {
		return false;
	}
	offset += (2 + ssctx->tag_len);

	if (offset + payload_len + ssctx->tag_len > BUFSIZE_16K) {
		return false;
	}

	if (!ssctx->iv_sent) {
		uint8_t *payload = malloc(payload_len);
		memcpy(payload, ssctx->cmd + 3, addr_len);
		memcpy(payload + addr_len, msg, len);

		bool ok = pgs_cryptor_encrypt(
			ssctx->encryptor, payload, payload_len,
			ssctx->wbuf + offset + payload_len /* tag */,
			ssctx->wbuf + offset, &ciphertext_len);
		pgs_ss_increase_cryptor_iv(ssctx, PGS_ENCRYPT);
		free(payload);
		ssctx->iv_sent = true;

		if (!ok || ciphertext_len != payload_len) {
			return false;
		}
	} else {
		bool ok = pgs_cryptor_encrypt(
			ssctx->encryptor, msg, len,
			ssctx->wbuf + offset + len /* tag */,
			ssctx->wbuf + offset, &ciphertext_len);
		pgs_ss_increase_cryptor_iv(ssctx, PGS_ENCRYPT);

		if (!ok || ciphertext_len != payload_len) {
			return false;
		}
	}

	*olen = offset + payload_len + ssctx->tag_len;
	evbuffer_add(outboundw, ssctx->wbuf, *olen);

	return true;
}
