#ifndef _PGS_OUTBOUND_H
#define _PGS_OUTBOUND_H

#include "acl.h"
#include "server/local.h"
#include "config.h"
#include "crypto.h"
#include "ssl.h"
#include "utils.h"

#include <stdint.h>
#include <stdbool.h>

#include <event2/event.h>
#include <event2/bufferevent.h>

#ifdef USE_MBEDTLS
#include <mbedtls/ssl.h>
#else
#include <openssl/ssl.h>
#endif

#define PGS_OUTBOUND_SET_READ_TIMEOUT(outbound, sec)                           \
	do {                                                                   \
		struct timeval tv;                                             \
		tv.tv_sec = sec;                                               \
		tv.tv_usec = 0;                                                \
		bufferevent_set_timeouts((outbound->bev), &tv, NULL);          \
	} while (0)

typedef struct pgs_session_outbound_s {
	bool ready;
	bool bypass;

	struct bufferevent *bev;
	const pgs_server_config_t *config;
	char *dest;
	int port;

	void *ctx;
} pgs_session_outbound_t;

typedef struct pgs_outbound_ctx_trojan_s {
	// sha224(password) + "\r\n" + cmd[1] + cmd.substr(3) + "\r\n"
	char *head;
	size_t head_len;
} pgs_outbound_ctx_trojan_t;

typedef struct pgs_outbound_ctx_v2ray_s {
	// key and iv for command part
	uint8_t iv[AES_128_CFB_IV_LEN];
	uint8_t key[AES_128_CFB_KEY_LEN];
	uint8_t riv[AES_128_CFB_IV_LEN];
	uint8_t rkey[AES_128_CFB_KEY_LEN];

	pgs_buffer_t *lrbuf;
	pgs_buffer_t *lwbuf;
	pgs_buffer_t *rrbuf;
	pgs_buffer_t *rwbuf;

	uint8_t target_addr[BUFSIZE_512]; /*atype(1) | addr | port(2)*/

	// for request header
	const uint8_t *cmd;
	size_t cmdlen;
	bool header_sent;
	uint8_t v;

	// for resp header
	bool header_recved;
	size_t resp_len;
	size_t target_addr_len;
	size_t remote_rbuf_pos;
	uint32_t resp_hash;

	// key and iv for data part
	uint8_t *data_enc_iv;
	uint8_t *data_enc_key;
	uint8_t *data_dec_iv;
	uint8_t *data_dec_key;
	size_t key_len;
	size_t iv_len;
	size_t tag_len;
	uint16_t enc_counter;
	uint16_t dec_counter;

	pgs_cryptor_t *encryptor;
	pgs_cryptor_t *decryptor;
	pgs_cryptor_type_t cipher;
} pgs_outbound_ctx_v2ray_t;

typedef struct pgs_outbound_ctx_ss_s {
	pgs_buffer_t *rbuf;
	pgs_buffer_t *wbuf;

	const uint8_t *cmd;
	size_t cmd_len;

	bool iv_sent;

	/* AEAD decode state machine */
	enum {
		READY = 0,
		WAIT_MORE_FOR_LEN, /* len(data) < 2 + tag_len */
		WAIT_MORE_FOR_PAYLOAD, /* len(data) < 2 + tag_len + payload_len + tag_len */
	} aead_decode_state;
	size_t plen;

	/* salt + ikm(pass) => encode key; len(salt) = len(key) */
	uint8_t *enc_key; /* random bytes, to send */
	uint8_t *enc_iv;
	uint8_t *dec_key; /* to receive by salt (AEAD) */
	uint8_t *dec_iv; /* to receive(AES) */
	uint8_t *ikm;
	uint8_t *enc_salt;
	size_t key_len;
	size_t iv_len;
	size_t tag_len;
	pgs_cryptor_t *encryptor;
	pgs_cryptor_t *decryptor;
	pgs_cryptor_type_t cipher;
} pgs_outbound_ctx_ss_t;

void socks5_dest_addr_parse(const uint8_t *cmd, size_t cmd_len, uint8_t *atype,
			    char **dest_ptr, int *port);

// trojan session context
pgs_outbound_ctx_trojan_t *
pgs_outbound_ctx_trojan_new(const uint8_t *encodepass, size_t passlen,
			    const uint8_t *cmd, size_t cmdlen);

void pgs_outbound_ctx_trojan_free(pgs_outbound_ctx_trojan_t *ctx);

// vmess context
pgs_outbound_ctx_v2ray_t *pgs_outbound_ctx_v2ray_new(const uint8_t *cmd,
						     size_t cmdlen,
						     pgs_cryptor_type_t cipher);
void pgs_outbound_ctx_v2ray_free(pgs_outbound_ctx_v2ray_t *ptr);

// shadowsocks context
pgs_outbound_ctx_ss_t *pgs_outbound_ctx_ss_new(const uint8_t *cmd,
					       size_t cmd_len,
					       const uint8_t *password,
					       size_t password_len,
					       pgs_cryptor_type_t cipher);
void pgs_outbound_ctx_ss_free(pgs_outbound_ctx_ss_t *ptr);

// outbound
void pgs_session_outbound_free(pgs_session_outbound_t *ptr);

bool pgs_session_trojan_outbound_init(
	pgs_session_outbound_t *ptr, pgs_logger_t *logger,
	const pgs_config_t *gconfig, const pgs_server_config_t *config,
	const uint8_t *cmd, size_t cmd_len, struct event_base *base,
	pgs_ssl_ctx_t *ssl_ctx, on_event_cb *event_cb, on_read_cb *read_cb,
	void *cb_ctx);

bool pgs_session_v2ray_outbound_init(
	pgs_session_outbound_t *ptr, pgs_logger_t *logger,
	const pgs_config_t *gconfig, const pgs_server_config_t *config,
	const uint8_t *cmd, size_t cmd_len, struct event_base *base,
	pgs_ssl_ctx_t *ssl_ctx, on_event_cb *event_cb, on_read_cb *read_cb,
	void *cb_ctx);

bool pgs_session_ss_outbound_init(
	pgs_session_outbound_t *ptr, pgs_logger_t *logger,
	const pgs_config_t *gconfig, const pgs_server_config_t *config,
	const uint8_t *cmd, size_t cmd_len, struct event_base *base,
	on_event_cb *event_cb, on_read_cb *read_cb, void *cb_ctx);

bool pgs_session_bypass_outbound_init(pgs_session_outbound_t *ptr,
				      pgs_logger_t *logger,
				      const pgs_config_t *gconfig,
				      struct event_base *base,
				      on_event_cb *event_cb,
				      on_read_cb *read_cb, void *cb_ctx);

pgs_session_outbound_t *pgs_session_outbound_new();

bool pgs_session_outbound_init(pgs_session_outbound_t *ptr, bool is_udp,
			       pgs_logger_t *logger,
			       const pgs_config_t *gconfig,
			       const pgs_server_config_t *config,
			       const uint8_t *cmd, size_t cmd_len,
			       pgs_local_server_t *local, void *cb_ctx);

static inline bool
pgs_session_outbound_is_ssl(const pgs_session_outbound_t *ptr)
{
	bool is_be_ssl = false;
	const pgs_server_config_t *config = ptr->config;

	if (IS_V2RAY_SERVER(config->server_type)) {
		pgs_config_extra_v2ray_t *vconf =
			(pgs_config_extra_v2ray_t *)config->extra;
		if (vconf->ssl.enabled) {
			is_be_ssl = true;
		}
	}
	if (IS_TROJAN_SERVER(config->server_type)) {
		is_be_ssl = true;
	}
	return is_be_ssl;
}

static inline bool
pgs_session_outbound_is_ssl_reused(const pgs_session_outbound_t *ptr)
{
	if (!pgs_session_outbound_is_ssl(ptr) || ptr->bypass)
		return false;
	bool reused = false;

#ifdef USE_MBEDTLS
	reused = false;
#else
	SSL *ssl = bufferevent_openssl_get_ssl(ptr->bev);
	reused = SSL_session_reused(ssl);
#endif

	return reused;
}

#endif
