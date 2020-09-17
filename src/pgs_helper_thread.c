#include "pgs_helper_thread.h"
#include "pgs_core.h"
#include "pgs_metrics.h"
#include <assert.h>

static void pgs_timer_cb(evutil_socket_t fd, short event, void *data);

/* timer */
static void pgs_timer_cb(evutil_socket_t fd, short event, void *data)
{
	pgs_timer_cb_arg_t *arg = data;
	// try to read metrics
	pgs_server_manager_tryrecv(arg->ctx->sm);
	// try to read all logs
	pgs_logger_tryrecv(arg->ctx->logger, arg->ctx->config->log_file);
	arg->tv.tv_sec = 1;
	arg->tv.tv_usec = 0;
	pgs_evtimer_add(arg->ev, &arg->tv);
}

static void pgs_metrics_timer_cb(evutil_socket_t fd, short event, void *data)
{
	pgs_timer_cb_arg_t *arg = data;
	for (int i = 0; i < arg->ctx->sm->server_len; i++) {
		get_metrics_g204_connect(arg->ctx->base, arg->ctx->sm, i,
					 arg->ctx->logger);
	}
	arg->tv.tv_sec = 15;
	arg->tv.tv_usec = 0;
	pgs_evtimer_add(arg->ev, &arg->tv);
}

void pgs_timer_init(int interval, pgs_timer_cb_t cb,
		    pgs_helper_thread_ctx_t *ptr)
{
	// FIXME: leaks
	pgs_timer_cb_arg_t *arg = pgs_malloc(sizeof(pgs_timer_cb_arg_t));
	arg->tv.tv_sec = interval;
	arg->tv.tv_usec = 0;
	arg->ctx = ptr;
	arg->ev = pgs_evtimer_new(ptr->base, cb, (void *)arg);

	pgs_evtimer_add(arg->ev, &arg->tv);
}

pgs_helper_thread_ctx_t *pgs_helper_thread_ctx_new(pgs_helper_thread_arg_t *arg)
{
	pgs_helper_thread_ctx_t *ptr =
		pgs_malloc(sizeof(pgs_helper_thread_ctx_t));
	ptr->tid = (pgs_tid)pthread_self();
	ptr->base = pgs_ev_base_new();
	ptr->config = arg->config;
	ptr->logger = arg->logger;
	ptr->sm = arg->sm;
	return ptr;
}

void pgs_helper_thread_ctx_free(pgs_helper_thread_ctx_t *ptr)
{
	if (ptr->base)
		pgs_ev_base_free(ptr->base);
	pgs_free(ptr);
}

void *pgs_helper_thread_start(void *data)
{
	pgs_helper_thread_arg_t *arg = (pgs_helper_thread_arg_t *)data;

	pgs_helper_thread_ctx_t *ctx = pgs_helper_thread_ctx_new(arg);

	// init timer cb
	pgs_timer_init(1, pgs_timer_cb, ctx);

	pgs_timer_init(1, pgs_metrics_timer_cb, ctx);

	pgs_ev_base_dispatch(ctx->base);

	pgs_helper_thread_ctx_free(ctx);

	return 0;
}
