#ifndef _PGS_STATS
#define _PGS_STATS

#include "pgs_server_manager.h"
#include "pgs_ev.h"

typedef struct pgs_stats_server_s pgs_stats_server_t;
typedef struct pgs_stats_server_ctx_s pgs_stats_server_ctx_t;
typedef struct pgs_stats_time_cb_arg_s pgs_stats_time_cb_arg_t;

struct pgs_stats_server_s {
	pgs_tid tid;
	pgs_ev_base_t *base;
	pgs_server_manager_t *sm;
	pgs_logger_t *logger;
	const pgs_config_t *config;
};

struct pgs_stats_server_ctx_s {
	pgs_mpsc_t *mpsc; // for logger
	pgs_server_manager_t *sm;
	const pgs_config_t *config;
};

struct pgs_stats_time_cb_arg_s {
	pgs_stats_server_t *server;
	pgs_event_t *ev;
};

pgs_stats_server_t *pgs_stats_server_new();
void pgs_stats_server_free(pgs_stats_server_t *ptr);
void pgs_stats_server_start(pgs_stats_server_t *ptr);
void *start_stats_server(void *data);

#endif

