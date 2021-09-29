#include "server/helper.h"
#include "server/metrics.h"
#include "server/control.h"

#include <assert.h>
#include <signal.h>
#include <pthread.h>

static void pgs_timer_cb(evutil_socket_t fd, short event, void *data)
{
	pgs_timer_cb_arg_t *arg = data;
	if (arg == NULL || arg->ctx == NULL || arg->ctx->config == NULL)
		goto error;
	// try to read all logs
	assert(arg->ctx->logger != NULL);
	assert(arg->ctx->config != NULL);
	assert(arg->ctx->config->log_file != NULL);
	pgs_logger_tryrecv(arg->ctx->logger, arg->ctx->config->log_file);
	arg->tv.tv_sec = 1;
	arg->tv.tv_usec = 0;
	evtimer_add(arg->ev, &arg->tv);
	return;

error:
	if (arg != NULL && arg->ev) {
		evtimer_del(arg->ev);
		free(arg);
	}
}

static void pgs_metrics_timer_cb(evutil_socket_t fd, short event, void *data)
{
	pgs_timer_cb_arg_t *arg = data;
	if (arg == NULL || arg->ctx == NULL)
		goto error;
	for (int i = 0; i < arg->ctx->sm->server_len; i++) {
		get_metrics_g204_connect(arg->ctx->base, arg->ctx->sm, i,
					 arg->ctx->logger, arg->ctx->ssl_ctx);
	}
	arg->tv.tv_sec = arg->ctx->config->ping_interval;
	arg->tv.tv_usec = 0;
	evtimer_add(arg->ev, &arg->tv);

	return;
error:
	if (arg != NULL && arg->ev) {
		evtimer_del(arg->ev);
		free(arg);
	}
}

void pgs_timer_init(int interval, pgs_timer_cb_t cb,
		    pgs_helper_thread_ctx_t *ptr)
{
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

	ptr->config = arg->config;
	ptr->logger = arg->logger;
	ptr->sm = arg->sm;
	ptr->ssl_ctx = arg->ssl_ctx;
	ptr->ctrl_fd = arg->ctrl_fd;
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
	pgs_helper_thread_ctx_t *ctx = (pgs_helper_thread_ctx_t *)data;

	ctx->tid = (uint32_t)pthread_self();
	ctx->logger->tid = (uint32_t)pthread_self();
	struct event_config *cfg = event_config_new();
	event_config_set_flag(cfg, EVENT_BASE_FLAG_NOLOCK);
	ctx->base = event_base_new_with_config(cfg);
	event_config_free(cfg);

	// timer for logger
	pgs_timer_init(1, pgs_timer_cb, ctx);

	// timer for connect and g204, interval can be setted by config
	pgs_timer_init(1, pgs_metrics_timer_cb, ctx);

	// control server
	pgs_control_server_ctx_t *cctx = pgs_control_server_start(
		ctx->ctrl_fd, ctx->base, ctx->sm, ctx->logger, ctx->config);

	event_base_dispatch(ctx->base);

	// drain logs
	pgs_logger_tryrecv(ctx->logger, ctx->config->log_file);
	printf("logs drained\n");

	pgs_control_server_ctx_destroy(cctx);

	// event_base_free(ctx->base);

	return 0;
}

void pgs_helper_thread_stop(pgs_helper_thread_ctx_t *ptr, int timeout)
{
	struct timeval tv;
	tv.tv_sec = timeout;
	tv.tv_usec = 0;

	event_base_loopexit(ptr->base, &tv);
}
