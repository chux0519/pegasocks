#ifndef _PGS_METRICS_H
#define _PGS_METRICS_H

#include "manager.h"
#include "session/session.h"
#include "codec/codec.h"
#include "ssl.h"
#include "utils.h"

#include <stdint.h>

#define PGS_FREE_METRICS_TASK(mctx) pgs_list_del(mctx->mtasks, mctx->node)

typedef struct pgs_metrics_task_ctx_s {
	struct event_base *base;
	struct evdns_base *dns_base;
	const pgs_server_config_t *config;
	pgs_server_manager_t *sm;
	int server_idx;
	pgs_logger_t *logger;
	pgs_session_outbound_t *outbound;
	struct timeval start_at;
	pgs_list_node_t *node;
	pgs_list_t *mtasks;
} pgs_metrics_task_ctx_t;

pgs_metrics_task_ctx_t *
get_metrics_g204_connect(int idx, struct event_base *base,
			 pgs_server_manager_t *sm, pgs_logger_t *logger,
			 pgs_ssl_ctx_t *ssl_ctx, pgs_list_t *mtasks);

pgs_metrics_task_ctx_t *
pgs_metrics_task_ctx_new(int i, struct event_base *base,
			 const pgs_server_config_t *config,
			 pgs_server_manager_t *sm, pgs_logger_t *logger,
			 pgs_session_outbound_t *outbound, pgs_list_t *mtasks);
void pgs_metrics_task_ctx_free(pgs_metrics_task_ctx_t *ptr);

#endif
