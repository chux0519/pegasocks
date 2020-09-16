#ifndef _PGS_METRICS
#define _PGS_METRICS

#include "pgs_server_manager.h"
#include "pgs_ev.h"
#include "pgs_session.h"
#include "pgs_codec.h"

typedef struct pgs_metrics_task_ctx_s pgs_metrics_task_ctx_t;

struct pgs_metrics_task_ctx_s {
	pgs_ev_base_t *base;
	pgs_ev_dns_base_t *dns_base;
	pgs_server_manager_t *sm;
	int server_idx;
	pgs_logger_t *logger;
	pgs_session_outbound_t *outbound;
	clock_t start_at;
};

void get_metrics_g204_connect(pgs_ev_base_t *base, pgs_server_manager_t *sm,
			      int idx, pgs_logger_t *logger);

pgs_metrics_task_ctx_t *
pgs_metrics_task_ctx_new(pgs_ev_base_t *base, pgs_server_manager_t *sm, int idx,
			 pgs_logger_t *logger,
			 pgs_session_outbound_t *outbound);
void pgs_metrics_task_ctx_free(pgs_metrics_task_ctx_t *ptr);

#endif
