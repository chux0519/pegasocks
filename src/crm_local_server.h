#ifndef _CRM_LOCAL_SERVER
#define _CRM_LOCAL_SERVER

#include "crm_core.h"
#include "crm_ev.h"
#include "crm_log.h"
#include "crm_config.h"

typedef struct crm_local_server_s crm_local_server_t;
typedef struct crm_local_server_ctx_s crm_local_server_ctx_t;

struct crm_local_server_s {
	crm_tid tid;
	crm_socket_t server_fd;
	crm_ev_base_t *base;
	crm_listener_t *listener;
	crm_logger_t *logger;
  // shared from main thread
  crm_config_t *config;
	// TODO: add dns_base and ssl ctx
};

struct crm_local_server_ctx_s {
	int fd;
	crm_mpsc_t *mpsc;
  crm_config_t *config;
};

static void new_conn_read_cb(struct bufferevent *bev, void *ctx);
static void new_conn_event_cb(struct bufferevent *bev, short events, void *ctx);

static void accept_error_cb(crm_listener_t *listener, void *ctx);
static void accept_conn_cb(crm_listener_t *listener, crm_socket_t fd,
			   crm_sockaddr_t *address, int socklen, void *ctx);

crm_local_server_t *crm_local_server_new(crm_local_server_ctx_t *ctx);
void crm_local_server_run(crm_local_server_t *local);
void crm_local_server_destroy(crm_local_server_t *local);

// thread entry point
void *start_local_server(void *data);

#endif
