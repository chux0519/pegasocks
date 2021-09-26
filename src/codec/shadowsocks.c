#include "codec/codec.h"
#include "crypto.h"

#include <event2/buffer.h>

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
		printf("len: %ld, [0]: %d, [1]: %d\n", payload_len, prefix[0],
		       prefix[1]);
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
	uint8_t *udp_packet = NULL;
	if (session->inbound->state == INBOUND_PROXY) {
		struct bufferevent *inbev = session->inbound->bev;
		struct evbuffer *inboundw = bufferevent_get_output(inbev);
		// TODO: decode and write
		pgs_session_debug(session, "remote -> local: %d", len);
	} else if (session->inbound->state == INBOUND_UDP_RELAY &&
		   session->inbound->udp_fd != -1) {
		// TODO:
	}
	return true;
}
