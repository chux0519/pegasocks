#ifndef _PGS_CONTROL_H
#define _PGS_CONTROL_H

#include <stdint.h>

#include <event2/bufferevent.h>

#include "manager.h"

// PING - PONG
// GET METRICS
// GET SERVER
// SET SERVER $number
// reload
// stop

typedef struct pgs_control_server_ctx_s pgs_control_server_ctx_t;

struct pgs_control_server_ctx_s {
	struct event_base *base;
	pgs_server_manager_t *sm;
	pgs_logger_t *logger;
	const pgs_config_t *config;
	struct evconnlistener *listener;
};

pgs_control_server_ctx_t *pgs_control_server_ctx_new();
void pgs_control_server_ctx_destroy(pgs_control_server_ctx_t *ptr);

pgs_control_server_ctx_t *pgs_control_server_start(int fd,
						   struct event_base *base,
						   pgs_server_manager_t *sm,
						   pgs_logger_t *logger,
						   const pgs_config_t *config);

#endif
