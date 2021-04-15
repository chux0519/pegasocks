#ifndef _PGS_LOCAL_SERVER
#define _PGS_LOCAL_SERVER

#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>

#include <stdint.h>

#include "pgs_log.h"
#include "pgs_config.h"
#include "pgs_server_manager.h"

typedef struct pgs_local_server_s pgs_local_server_t;
typedef struct pgs_local_server_ctx_s pgs_local_server_ctx_t;

struct pgs_local_server_s {
	uint32_t tid;
	int server_fd;
	int udp_fd;
	struct event_base *base;
	struct evdns_base *dns_base;
	struct evconnlistener *listener;
	struct event *udp_event;
	pgs_logger_t *logger;
	// shared from main thread, read only
	pgs_config_t *config;
	pgs_server_manager_t *sm;
};

struct pgs_local_server_ctx_s {
	int fd;
	int udp_fd;
	pgs_mpsc_t *mpsc;
	pgs_config_t *config;
	pgs_server_manager_t *sm;
};

pgs_local_server_t *pgs_local_server_new(pgs_local_server_ctx_t *ctx);
void pgs_local_server_run(pgs_local_server_t *local);
void pgs_local_server_destroy(pgs_local_server_t *local);

void *start_local_server(void *data);

#endif
