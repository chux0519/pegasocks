#ifndef _PGS_LOCAL_SERVER
#define _PGS_LOCAL_SERVER

#include "pgs_core.h"
#include "pgs_ev.h"
#include "pgs_log.h"
#include "pgs_config.h"

typedef struct pgs_local_server_s pgs_local_server_t;
typedef struct pgs_local_server_ctx_s pgs_local_server_ctx_t;

struct pgs_local_server_s {
	pgs_tid tid;
	pgs_socket_t server_fd;
	pgs_ev_base_t *base;
	pgs_ev_dns_base_t *dns_base;
	pgs_listener_t *listener;
	pgs_logger_t *logger;
	// shared from main thread, read only
	pgs_config_t *config;
};

struct pgs_local_server_ctx_s {
	int fd;
	pgs_mpsc_t *mpsc;
	pgs_config_t *config;
};

pgs_local_server_t *pgs_local_server_new(pgs_local_server_ctx_t *ctx);
void pgs_local_server_run(pgs_local_server_t *local);
void pgs_local_server_destroy(pgs_local_server_t *local);

void *start_local_server(void *data);

#endif
