#include "server/helper.h"
#include "server/metrics.h"
#include "server/control.h"

#include <assert.h>
#include <signal.h>

static void pgs_timer_cb(evutil_socket_t fd, short event, void *data)
{
	pgs_timer_cb_arg_t *arg = data;
	// try to read all logs
	pgs_logger_tryrecv(arg->ctx->logger, arg->ctx->config->log_file);
	arg->tv.tv_sec = 1;
	arg->tv.tv_usec = 0;
	evtimer_add(arg->ev, &arg->tv);
}

static void pgs_metrics_timer_cb(evutil_socket_t fd, short event, void *data)
{
	pgs_timer_cb_arg_t *arg = data;
	for (int i = 0; i < arg->ctx->sm->server_len; i++) {
		get_metrics_g204_connect(arg->ctx->base, arg->ctx->sm, i,
					 arg->ctx->logger, arg->ctx->ssl_ctx);
	}
	arg->tv.tv_sec = arg->ctx->config->ping_interval;
	arg->tv.tv_usec = 0;
	evtimer_add(arg->ev, &arg->tv);
}

void pgs_timer_init(int interval, pgs_timer_cb_t cb,
		    pgs_helper_thread_ctx_t *ptr)
{
	// FIXME: leaks?
	pgs_timer_cb_arg_t *arg = malloc(sizeof(pgs_timer_cb_arg_t));
	arg->tv.tv_sec = interval;
	arg->tv.tv_usec = 0;
	arg->ctx = ptr;
	arg->ev = evtimer_new(ptr->base, cb, (void *)arg);

	evtimer_add(arg->ev, &arg->tv);
}

pgs_helper_thread_ctx_t *pgs_helper_thread_ctx_new(pgs_helper_thread_arg_t *arg)
{
	pgs_helper_thread_ctx_t *ptr = malloc(sizeof(pgs_helper_thread_ctx_t));
	ptr->tid = (uint32_t)pthread_self();
	ptr->base = event_base_new();
	ptr->config = arg->config;
	ptr->logger = arg->logger;
	ptr->sm = arg->sm;
	ptr->ssl_ctx = arg->ssl_ctx;
	return ptr;
}

void pgs_helper_thread_ctx_free(pgs_helper_thread_ctx_t *ptr)
{
	if (ptr->base)
		event_base_free(ptr->base);
	free(ptr);
}

void *pgs_helper_thread_start(void *data)
{
	pgs_helper_thread_arg_t *arg = (pgs_helper_thread_arg_t *)data;

	pgs_helper_thread_ctx_t *ctx = pgs_helper_thread_ctx_new(arg);

	// timer for logger
	pgs_timer_init(1, pgs_timer_cb, ctx);

	// timer for connect and g204, interval can be setted by config
	pgs_timer_init(1, pgs_metrics_timer_cb, ctx);

	// control server
	pgs_control_server_start(arg->ctrl_fd, ctx->base, ctx->sm, ctx->logger,
				 ctx->config);

	event_base_dispatch(ctx->base);

	pgs_helper_thread_ctx_free(ctx);

	return 0;
}
