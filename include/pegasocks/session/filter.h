#ifndef _PGS_FILTER_H
#define _PGS_FILTER_H

#include "session.h"

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef enum { FILTER_DIR_ENCODE, FILTER_DIR_DECODE } pgs_filter_direction;
typedef enum {
	FILTER_SUCCESS = 0,
	FILTER_FAIL,
	FILTER_NEED_MORE_DATA,
	FILTER_SKIP,
} pgs_filter_result;
typedef enum {
	FILTER_TROJAN = 0,
	FITLER_TROJAN_UDP,
	FITLER_WEBSOCKET,
	FILTER_SS,
} pgs_filter_type;
typedef struct pgs_filter_s {
	pgs_filter_type type;

	void *ctx;

	void (*free)(void *ctx);
	int (*encode)(void *ctx, const uint8_t *msg, size_t len, uint8_t **out,
		      size_t *olen);
	int (*decode)(void *ctx, const uint8_t *msg, size_t len, uint8_t **out,
		      size_t *olen, size_t *clen /* consumeed length */);
} pgs_filter_t;

pgs_filter_t *pgs_filter_new(pgs_filter_type, const pgs_session_t *);
void pgs_filter_free(pgs_filter_t *);

typedef struct pgs_trojan_filter_ctx_s {
	bool head_sent;
	// sha224(password) + "\r\n" + cmd[1] + cmd.substr(3) + "\r\n"
	char *head;
	size_t head_len;
} pgs_trojan_filter_ctx_t;

typedef struct pgs_ss_filter_ctx_s {
	const uint8_t *cmd;
	size_t cmd_len;

	bool iv_sent;
	bool is_udp;

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
} pgs_ss_filter_ctx_t;

pgs_trojan_filter_ctx_t *pgs_trojan_filter_ctx_new(const pgs_session_t *);
void pgs_trojan_filter_ctx_free(pgs_trojan_filter_ctx_t *);

typedef struct pgs_ws_header_s {
	int fin;
	int opcode;
	int mask;
	uint64_t payload_len; /* for vmess and trojan, size_t is big enough */
	size_t header_len;
} pgs_ws_header_t;

typedef struct pgs_ws_filter_ctx_s {
	int opcode;
	pgs_ws_header_t header;
} pgs_ws_filter_ctx_t;

pgs_ws_filter_ctx_t *pgs_ws_filter_ctx_new(const pgs_session_t *);
void pgs_ws_filter_ctx_free(pgs_ws_filter_ctx_t *);

pgs_ss_filter_ctx_t *pgs_ss_filter_ctx_new(const pgs_server_config_t *,
					   const pgs_socks5_cmd_t *);
void pgs_ss_filter_ctx_free(pgs_ss_filter_ctx_t *);

#endif