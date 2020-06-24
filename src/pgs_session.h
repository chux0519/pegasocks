#ifndef _PGS_SESSION
#define _PGS_SESSION

#include "pgs_core.h"
#include "pgs_conn.h"
#include "pgs_local_server.h"
#include "pgs_socks5.h"

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

struct pgs_session_s {
	pgs_session_inbound_t *inbound;
	pgs_session_outbound_t *outbound;
	pgs_local_server_t *local_server;
	// socks5 state machine
	pgs_socks5_t fsm_socks5;
};

struct pgs_session_inbound_s {
	pgs_conn_t *conn;
	pgs_bev_t *bev;
};

struct pgs_session_outbound_s {
	pgs_bev_t *bev;
	const pgs_server_config_t *config;
	void *ctx;
};

struct pgs_trojansession_ctx_s {
	// sha224(password) + "\r\n" + cmd[1] + cmd.substr(3) + "\r\n"
	char *head;
	pgs_size_t head_len;
	bool upgraded;
};

// trojan session context
pgs_trojansession_ctx_t *pgs_trojansession_ctx_new(const char *encodepass,
						   pgs_size_t passlen,
						   const char *cmd,
						   pgs_size_t cmdlen);
void pgs_trojansession_ctx_free(pgs_trojansession_ctx_t *ctx);

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
