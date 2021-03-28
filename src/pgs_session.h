#ifndef _PGS_SESSION
#define _PGS_SESSION

#include "pgs_util.h"
#include "pgs_local_server.h"
#include "pgs_server_manager.h"
#include "pgs_crypto.h"
#include "pgs_defs.h"
#include "pgs_ssl.h"

#include <stdint.h>

#define pgs_session_debug(session, ...)                                        \
	pgs_logger_debug(session->local_server->logger, __VA_ARGS__)
#define pgs_session_info(session, ...)                                         \
	pgs_logger_info(session->local_server->logger, __VA_ARGS__)
#define pgs_session_warn(session, ...)                                         \
	pgs_logger_warn(session->local_server->logger, __VA_ARGS__)
#define pgs_session_error(session, ...)                                        \
	pgs_logger_error(session->local_server->logger, __VA_ARGS__)
#define pgs_session_debug_buffer(session, buf, len)                            \
	pgs_logger_debug_buffer(session->local_server->logger, buf, len)

typedef struct pgs_session_s pgs_session_t;
typedef struct pgs_session_inbound_s pgs_session_inbound_t;
typedef struct pgs_session_outbound_s pgs_session_outbound_t;
typedef struct pgs_trojansession_ctx_s pgs_trojansession_ctx_t;
typedef struct pgs_vmess_ctx_s pgs_vmess_ctx_t;
typedef struct pgs_vmess_resp_s pgs_vmess_resp_t;
typedef enum {
	INBOUND_AUTH,
	INBOUND_CMD,
	INBOUND_PROXY,
	INBOUND_ERR
} pgs_session_inbound_state;
typedef void(on_event_cb)(struct bufferevent *bev, short events, void *ctx);
typedef void(on_read_cb)(struct bufferevent *bev, void *ctx);
typedef void(free_ctx_fn)(void *ctx);
typedef struct pgs_session_outbound_cbs_s pgs_session_outbound_cbs_t;
typedef struct pgs_session_inbound_cbs_s pgs_session_inbound_cbs_t;

struct pgs_session_s {
	pgs_session_inbound_t *inbound;
	pgs_session_outbound_t *outbound;
	pgs_local_server_t *local_server;
	pgs_server_session_stats_t *metrics;
};

struct pgs_session_inbound_s {
	struct bufferevent *bev;
	pgs_session_inbound_state state;
	uint8_t *cmd;
	uint64_t cmdlen;
};

struct pgs_session_outbound_s {
	struct bufferevent *bev;
	const pgs_server_config_t *config;
	int config_idx;
	char *dest;
	int port;
	void *ctx;
};

struct pgs_session_outbound_cbs_s {
	on_event_cb *on_trojan_ws_remote_event;
	on_event_cb *on_trojan_gfw_remote_event;
	on_event_cb *on_v2ray_ws_remote_event;
	on_event_cb *on_v2ray_tcp_remote_event;
	on_read_cb *on_trojan_ws_remote_read;
	on_read_cb *on_trojan_gfw_remote_read;
	on_read_cb *on_v2ray_ws_remote_read;
	on_read_cb *on_v2ray_tcp_remote_read;
};

struct pgs_session_inbound_cbs_s {
	on_event_cb *on_local_event;
	on_read_cb *on_trojan_ws_local_read;
	on_read_cb *on_trojan_gfw_local_read;
	on_read_cb *on_v2ray_ws_local_read;
	on_read_cb *on_v2ray_tcp_local_read;
};

struct pgs_trojansession_ctx_s {
	// sha224(password) + "\r\n" + cmd[1] + cmd.substr(3) + "\r\n"
	char *head;
	uint64_t head_len;
	bool connected;
};

struct pgs_vmess_ctx_s {
	// for aes codec
	char iv[AES_128_CFB_IV_LEN];
	char key[AES_128_CFB_KEY_LEN];
	char riv[AES_128_CFB_IV_LEN];
	char rkey[AES_128_CFB_KEY_LEN];
	uint8_t local_rbuf[BUFSIZE_16K];
	uint8_t local_wbuf[BUFSIZE_16K];
	uint8_t remote_rbuf[BUFSIZE_16K];
	uint8_t remote_wbuf[BUFSIZE_16K];
	// for ws state
	bool connected;
	// for request header
	const uint8_t *cmd;
	uint64_t cmdlen;
	bool header_sent;
	// for resp header
	bool header_recved;
	struct pgs_vmess_resp_s {
		uint8_t v;
		uint8_t opt;
		uint8_t cmd;
		uint8_t m;
	} resp_meta;
	uint64_t resp_len;
	uint64_t remote_rbuf_pos;
	uint32_t resp_hash;
	pgs_base_cryptor_t *encryptor;
	pgs_base_cryptor_t *decryptor;
	pgs_v2rayserver_secure_t secure;
};

// trojan session context
pgs_trojansession_ctx_t *pgs_trojansession_ctx_new(const uint8_t *encodepass,
						   uint64_t passlen,
						   const uint8_t *cmd,
						   uint64_t cmdlen);
void pgs_trojansession_ctx_free(pgs_trojansession_ctx_t *ctx);

// vmess context
pgs_vmess_ctx_t *pgs_vmess_ctx_new(const uint8_t *cmd, uint64_t cmdlen,
				   pgs_v2rayserver_secure_t secure);
void pgs_vmess_ctx_free(pgs_vmess_ctx_t *ptr);

// inbound
pgs_session_inbound_t *pgs_session_inbound_new(struct bufferevent *bev);
void pgs_session_inbound_free(pgs_session_inbound_t *sb);

// outbound
pgs_session_outbound_t *
pgs_session_outbound_new(const pgs_server_config_t *config, int config_idx,
			 const uint8_t *cmd, uint64_t cmd_len,
			 pgs_logger_t *logger, struct event_base *base,
			 struct evdns_base *dns_base, struct bufferevent *inbev,
			 pgs_session_inbound_cbs_t inbound_cbs,
			 pgs_session_outbound_cbs_t outbound_cbs, void *cb_ctx,
			 free_ctx_fn *free_cb_ctx);
void pgs_session_outbound_free(pgs_session_outbound_t *outbound);

// session
pgs_session_t *pgs_session_new(int fd, pgs_local_server_t *local_server);
void pgs_session_free(pgs_session_t *session);
void pgs_session_start(pgs_session_t *session);

#endif
