#ifndef _PGS_SESSION
#define _PGS_SESSION

#include "pgs_util.h"
#include "pgs_core.h"
#include "pgs_conn.h"
#include "pgs_local_server.h"
#include "pgs_socks5.h"
#include "pgs_server_manager.h"
#include "pgs_crypto.h"

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

struct pgs_session_s {
	pgs_session_inbound_t *inbound;
	pgs_session_outbound_t *outbound;
	pgs_local_server_t *local_server;
	// socks5 state machine
	pgs_socks5_t fsm_socks5;
	pgs_server_session_stats_t *metrics;
};

struct pgs_session_inbound_s {
	pgs_conn_t *conn;
	pgs_bev_t *bev;
};

struct pgs_session_outbound_s {
	pgs_bev_t *bev;
	const pgs_server_config_t *config;
	int config_idx;
	char *dest;
	int port;
	void *ctx;
};

struct pgs_trojansession_ctx_s {
	// sha224(password) + "\r\n" + cmd[1] + cmd.substr(3) + "\r\n"
	char *head;
	pgs_size_t head_len;
	bool connected;
};

struct pgs_vmess_ctx_s {
	// for aes codec
	char iv[AES_128_CFB_IV_LEN];
	char key[AES_128_CFB_KEY_LEN];
	char riv[AES_128_CFB_IV_LEN];
	char rkey[AES_128_CFB_KEY_LEN];
	pgs_buf_t local_rbuf[_PGS_BUFSIZE];
	pgs_buf_t local_wbuf[_PGS_BUFSIZE];
	pgs_buf_t remote_rbuf[_PGS_BUFSIZE];
	pgs_buf_t remote_wbuf[_PGS_BUFSIZE];
	// for ws state
	bool connected;
	// for request header
	char *cmd;
	pgs_size_t cmdlen;
	bool header_sent;
	// for resp header
	bool header_recved;
	struct pgs_vmess_resp_s {
		uint8_t v;
		uint8_t opt;
		uint8_t cmd;
		uint8_t m;
	} resp_meta;
	bool body_recved;
	pgs_size_t resp_len;
	pgs_size_t chunk_len;
	pgs_size_t remote_rbuf_pos;
	uint32_t resp_hash;
	pgs_aes_cryptor_t *encryptor;
	pgs_aes_cryptor_t *decryptor;
};

// trojan session context
pgs_trojansession_ctx_t *pgs_trojansession_ctx_new(const char *encodepass,
						   pgs_size_t passlen,
						   const char *cmd,
						   pgs_size_t cmdlen);
void pgs_trojansession_ctx_free(pgs_trojansession_ctx_t *ctx);

// vmess context
pgs_vmess_ctx_t *pgs_vmess_ctx_new(const char *cmd, pgs_size_t cmdlen);
void pgs_vmess_ctx_free(pgs_vmess_ctx_t *ptr);

// inbound
pgs_session_inbound_t *pgs_session_inbound_new(pgs_conn_t *conn,
					       pgs_bev_t *bev);
void pgs_session_inbound_free(pgs_session_inbound_t *sb);

// outbound
pgs_session_outbound_t *
pgs_session_outbound_new(pgs_session_t *session,
			 const pgs_server_config_t *config);
void pgs_session_outbound_free(pgs_session_outbound_t *outbound);
void pgs_session_outbound_run(pgs_session_t *session);

// session
pgs_session_t *pgs_session_new(pgs_socket_t fd,
			       pgs_local_server_t *local_server);
void pgs_session_free(pgs_session_t *session);
void pgs_session_start(pgs_session_t *session);

#endif
