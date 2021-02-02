#ifndef _PGS_HELPER_THREAD
#define _PGS_HELPER_THREAD

#include <event2/util.h>

#include "pgs_server_manager.h"

typedef struct pgs_helper_thread_ctx_s pgs_helper_thread_ctx_t;
typedef struct pgs_helper_thread_arg_s pgs_helper_thread_arg_t;
typedef struct pgs_timer_cb_arg_s pgs_timer_cb_arg_t;
typedef void(pgs_timer_cb_t)(evutil_socket_t fd, short event, void *data);

struct pgs_timer_cb_arg_s {
	struct event *ev;
	struct timeval tv;
	pgs_helper_thread_ctx_t *ctx;
};

struct pgs_helper_thread_ctx_s {
	pgs_tid tid;
	struct event_base *base;
	pgs_server_manager_t *sm;
	pgs_logger_t *logger;
	const pgs_config_t *config;
};

struct pgs_helper_thread_arg_s {
	pgs_server_manager_t *sm;
	pgs_logger_t *logger;
	const pgs_config_t *config;
	int ctrl_fd;
};

pgs_helper_thread_ctx_t *
pgs_helper_thread_ctx_new(pgs_helper_thread_arg_t *arg);
void pgs_helper_thread_ctx_free(pgs_helper_thread_ctx_t *ptr);

void *pgs_helper_thread_start(void *data);
void pgs_timer_init(int interval, pgs_timer_cb_t, pgs_helper_thread_ctx_t *ptr);

#endif
