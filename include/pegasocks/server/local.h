#ifndef _PGS_LOCAL_SERVER_H
#define _PGS_LOCAL_SERVER_H

#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>

#include <stdint.h>

#include "acl.h"
#include "log.h"
#include "config.h"
#include "manager.h"
#include "ssl.h"
#include "utils.h"

#define UDP_PACKET_HEADER_SIZE (1 + 28 + 2 + 64)
#define DEFAULT_MTU 1397 // 1492 - UDP_PACKET_HEADER_SIZE

typedef struct pgs_local_server_s {
	uint32_t tid;
	int server_fd;
	int server_udp_fd;
	struct event_base *base;
	struct evdns_base *dns_base;
	struct evconnlistener *listener;
	struct event *udp_listener;
	pgs_logger_t *logger;

	// to graceful shutdown
	pgs_list_t *sessions;
	struct event *ev_term;

	// shared from main thread, read only
	pgs_config_t *config;
	pgs_server_manager_t *sm;
	pgs_acl_t *acl;
	pgs_ssl_ctx_t *ssl_ctx;
} pgs_local_server_t;

typedef struct pgs_local_server_ctx_s {
	int fd;
	int ufd;
	pgs_mpsc_t *mpsc;
	pgs_config_t *config;
	pgs_server_manager_t *sm;
	pgs_acl_t *acl;
	pgs_ssl_ctx_t *ssl_ctx;

	void **local_server_ref; /* it will be used to stop the server from other threads */
} pgs_local_server_ctx_t;

pgs_local_server_t *pgs_local_server_new(int fd, int ufd, pgs_mpsc_t *mpsc,
					 pgs_config_t *config, pgs_acl_t *acl,
					 pgs_server_manager_t *sm,
					 pgs_ssl_ctx_t *ssl_ctx);
void pgs_local_server_destroy(pgs_local_server_t *local);

void *start_local_server(void *data);

#endif
