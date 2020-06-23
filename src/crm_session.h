#ifndef _CRM_SESSION
#define _CRM_SESSION

#include "crm_core.h"
#include "crm_conn.h"
#include "crm_local_server.h"
#include "crm_socks5.h"

#define crm_session_debug(session, ...)                                        \
	crm_logger_debug(session->local_server->logger, __VA_ARGS__)
#define crm_session_info(session, ...)                                         \
	crm_logger_info(session->local_server->logger, __VA_ARGS__)
#define crm_session_warn(session, ...)                                         \
	crm_logger_warn(session->local_server->logger, __VA_ARGS__)
#define crm_session_error(session, ...)                                        \
	crm_logger_error(session->local_server->logger, __VA_ARGS__)
#define crm_session_debug_buffer(session, buf, len)                            \
	crm_logger_debug_buffer(session->local_server->logger, buf, len)

typedef struct crm_session_s crm_session_t;
typedef struct crm_session_inbound_s crm_session_inbound_t;
typedef struct crm_session_outbound_s crm_session_outbound_t;
typedef struct crm_trojansession_ctx_s crm_trojansession_ctx_t;

struct crm_session_s {
	crm_session_inbound_t *inbound;
	crm_session_outbound_t *outbound;
	crm_local_server_t *local_server;
	// socks5 state machine
	crm_socks5_t fsm_socks5;
};

struct crm_session_inbound_s {
	crm_conn_t *conn;
	crm_bev_t *bev;
};

struct crm_session_outbound_s {
	crm_bev_t *bev;
	const crm_server_config_t *config;
	void *ctx;
};

struct crm_trojansession_ctx_s {
	// sha224(password) + "\r\n" + cmd[1] + cmd.substr(3) + "\r\n"
	char *head;
	crm_size_t head_len;
	bool upgraded;
};

// trojan session context
crm_trojansession_ctx_t *crm_trojansession_ctx_new(const char *encodepass,
						   crm_size_t passlen,
						   const char *cmd,
						   crm_size_t cmdlen);
void crm_trojansession_ctx_free(crm_trojansession_ctx_t *ctx);

// inbound
crm_session_inbound_t *crm_session_inbound_new(crm_conn_t *conn,
					       crm_bev_t *bev);
void crm_session_inbound_free(crm_session_inbound_t *sb);

// outbound
crm_session_outbound_t *
crm_session_outbound_new(crm_session_t *session,
			 const crm_server_config_t *config);
void crm_session_outbound_free(crm_session_outbound_t *outbound);
void crm_session_outbound_run(crm_session_t *session);

// session
crm_session_t *crm_session_new(crm_socket_t fd,
			       crm_local_server_t *local_server);
void crm_session_free(crm_session_t *session);
void crm_session_start(crm_session_t *session);

#endif
