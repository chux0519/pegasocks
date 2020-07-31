#ifndef _PGS_HELPER_THREAD
#define _PGS_HELPER_THREAD

#include "pgs_server_manager.h"
#include "pgs_ev.h"

typedef struct pgs_helper_thread_ctx_s pgs_helper_thread_ctx_t;
typedef struct pgs_helper_thread_arg_s pgs_helper_thread_arg_t;
typedef struct pgs_timer_cb_arg_s pgs_timer_cb_arg_t;

struct pgs_timer_cb_arg_s {
	pgs_event_t *ev;
	struct timeval tv;
	pgs_helper_thread_ctx_t *ctx;
};

struct pgs_helper_thread_ctx_s {
	pgs_tid tid;
	pgs_ev_base_t *base;
	pgs_server_manager_t *sm;
	pgs_logger_t *logger;
	const pgs_config_t *config;
};

struct pgs_helper_thread_arg_s {
	pgs_server_manager_t *sm;
	pgs_logger_t *logger;
	const pgs_config_t *config;
};

pgs_helper_thread_ctx_t *
pgs_helper_thread_ctx_new(pgs_helper_thread_arg_t *arg);
void pgs_helper_thread_ctx_free(pgs_helper_thread_ctx_t *ptr);

void *pgs_helper_thread_start(void *data);
void pgs_timer_init(pgs_helper_thread_ctx_t *ptr);

#endif
