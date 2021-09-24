#ifndef _PGS_OUTBOUND_H
#define _PGS_OUTBOUND_H

#include "optional/acl.h"
#include "local_server.h"
#include "config.h"
#include "crypto.h"

#include <stdint.h>
#include <stdbool.h>

#include <event2/event.h>
#include <event2/bufferevent.h>

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
	uint64_t head_len;
} pgs_outbound_ctx_trojan_t;

typedef struct pgs_outbound_ctx_v2ray_s {
	// for aes codec
	char iv[AES_128_CFB_IV_LEN];
	char key[AES_128_CFB_KEY_LEN];
	char riv[AES_128_CFB_IV_LEN];
	char rkey[AES_128_CFB_KEY_LEN];
	uint8_t local_rbuf[BUFSIZE_16K];
	uint8_t local_wbuf[BUFSIZE_16K];
	uint8_t remote_rbuf[BUFSIZE_16K];
	uint8_t remote_wbuf[BUFSIZE_16K];
	uint8_t target_addr[BUFSIZE_512]; /*atype(1) | addr | port(2)*/
	// for request header
	const uint8_t *cmd;
	uint64_t cmdlen;
	bool header_sent;
	uint8_t v;
	// for resp header
	bool header_recved;
	uint64_t resp_len;
	uint64_t target_addr_len;
	uint64_t remote_rbuf_pos;
	uint32_t resp_hash;
	pgs_base_cryptor_t *encryptor;
	pgs_base_cryptor_t *decryptor;
	pgs_v2ray_secure_t secure;
} pgs_outbound_ctx_v2ray_t;

typedef struct pgs_outbound_ctx_ss_s {
	pgs_ss_method_t method;
	/* salt + ikm(pass) => encode key; len(salt) = len(key) */
	uint8_t *enc_salt; /* random bytes, to send */
	uint8_t *dec_salt; /* to receive */
	pgs_base_cryptor_t *encryptor;
	pgs_base_cryptor_t *decryptor;
} pgs_outbound_ctx_ss_t;

void socks5_dest_addr_parse(const uint8_t *cmd, uint64_t cmd_len,
			    pgs_acl_t *acl, bool *proxy, char **dest_ptr,
			    int *port);

// trojan session context
pgs_outbound_ctx_trojan_t *
pgs_outbound_ctx_trojan_new(const uint8_t *encodepass, uint64_t passlen,
			    const uint8_t *cmd, uint64_t cmdlen);

void pgs_outbound_ctx_trojan_free(pgs_outbound_ctx_trojan_t *ctx);

// vmess context
pgs_outbound_ctx_v2ray_t *pgs_outbound_ctx_v2ray_new(const uint8_t *cmd,
						     uint64_t cmdlen,
						     pgs_v2ray_secure_t secure);
void pgs_outbound_ctx_v2ray_free(pgs_outbound_ctx_v2ray_t *ptr);

// outbound
void pgs_session_outbound_free(pgs_session_outbound_t *ptr);

bool pgs_session_trojan_outbound_init(pgs_session_outbound_t *ptr,
				      const pgs_server_config_t *config,
				      const uint8_t *cmd, uint64_t cmd_len,
				      struct event_base *base,
				      on_event_cb *event_cb,
				      on_read_cb *read_cb, void *cb_ctx);

bool pgs_session_v2ray_outbound_init(pgs_session_outbound_t *ptr,
				     const pgs_server_config_t *config,
				     const uint8_t *cmd, uint64_t cmd_len,
				     struct event_base *base,
				     on_event_cb *event_cb, on_read_cb *read_cb,
				     void *cb_ctx);

bool pgs_session_bypass_outbound_init(pgs_session_outbound_t *ptr,
				      struct event_base *base,
				      on_event_cb *event_cb,
				      on_read_cb *read_cb, void *cb_ctx);

pgs_session_outbound_t *pgs_session_outbound_new();

bool pgs_session_outbound_init(pgs_session_outbound_t *ptr, bool is_udp,
			       const pgs_config_t *gconfig,
			       const pgs_server_config_t *config,
			       const uint8_t *cmd, uint64_t cmd_len,
			       pgs_local_server_t *local, void *cb_ctx);

#endif
