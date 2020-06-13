#ifndef _CRM_SESSION
#define _CRM_SESSION

#include "crm_core.h"
#include "crm_conn.h"
#include "crm_local_server.h"
#include "crm_socks5.h"

typedef struct crm_session_s crm_session_t;

struct crm_session_s {
	crm_conn_t *conn;
	crm_local_server_t *local_server;
	crm_socks5_t fsm_socks5;
};

static void do_socks5_handshake(struct bufferevent *bev, void *ctx);
static void other_session_event_cb(struct bufferevent *bev, short events,
				   void *ctx);

crm_session_t *crm_session_new(crm_socket_t fd,
			       crm_local_server_t *local_server);
void crm_session_free(crm_session_t *session);

void crm_session_start(crm_session_t *session);

#endif
