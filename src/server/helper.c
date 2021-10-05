#include "server/helper.h"
#include "server/metrics.h"
#include "server/control.h"

#include <assert.h>
#include <signal.h>
#include <pthread.h>

static void pgs_timer_cb(evutil_socket_t fd, short event, void *data)
{
	pgs_timer_t *arg = data;
	assert(arg->ctx->logger != NULL);
	assert(arg->ctx->config != NULL);
	assert(arg->ctx->config->log_file != NULL);
	pgs_logger_tryrecv(arg->ctx->logger, arg->ctx->config->log_file);
	arg->tv.tv_sec = 1;
	arg->tv.tv_usec = 0;
	evtimer_add(arg->ev, &arg->tv);
	return;
}

static void pgs_metrics_timer_cb(evutil_socket_t fd, short event, void *data)
{
	pgs_timer_t *arg = data;
	for (int i = 0; i < arg->ctx->sm->server_len; i++) {
		pgs_metrics_task_ctx_t *t = get_metrics_g204_connect(
			i, arg->ctx->base, arg->ctx->sm, arg->ctx->logger,
			arg->ctx->ssl_ctx, arg->ctx->mtasks);
		if (t) {
			pgs_list_add(arg->ctx->mtasks, t->node);
		}
	}
	arg->tv.tv_sec = arg->ctx->config->ping_interval;
	arg->tv.tv_usec = 0;
	evtimer_add(arg->ev, &arg->tv);

	return;
}

static void pgs_helper_term(int sig, short events, void *arg)
{
	event_base_loopbreak(arg);
}

pgs_timer_t *pgs_timer_init(int interval, pgs_timer_cb_t cb,
			    pgs_helper_thread_t *ptr)
{
	pgs_timer_t *arg = malloc(sizeof(pgs_timer_t));
	arg->tv.tv_sec = interval;
	arg->tv.tv_usec = 0;
	arg->ctx = ptr;
	arg->ev = evtimer_new(ptr->base, cb, (void *)arg);
	evtimer_add(arg->ev, &arg->tv);
	return arg;
}

void pgs_timer_destroy(pgs_timer_t *ctx)
{
	if (ctx->ev) {
		evtimer_del(ctx->ev);
		event_free(ctx->ev);
	}
	if (ctx)
		free(ctx);
}

pgs_helper_thread_t *pgs_helper_thread_new(int cfd, pgs_config_t *config,
					   pgs_logger_t *logger,
					   pgs_server_manager_t *sm,
					   pgs_ssl_ctx_t *ssl_ctx)
{
	pgs_helper_thread_t *ptr = malloc(sizeof(pgs_helper_thread_t));

	struct event_config *cfg = event_config_new();
	event_config_set_flag(cfg, EVENT_BASE_FLAG_NOLOCK);
	ptr->base = event_base_new_with_config(cfg);
	event_config_free(cfg);

	ptr->control_server =
		pgs_control_server_start(cfd, ptr->base, sm, logger, config);

	ptr->ev_term = evuser_new(ptr->base, pgs_helper_term, ptr->base);

	ptr->mtasks = pgs_list_new();
	ptr->mtasks->free = (void *)pgs_metrics_task_ctx_free;

	ptr->tid = (uint32_t)pthread_self();
	ptr->cfd = cfd;
	ptr->config = config;
	ptr->logger = logger;
	ptr->sm = sm;
	ptr->ssl_ctx = ssl_ctx;
	return ptr;
}

void pgs_helper_thread_free(pgs_helper_thread_t *ptr)
{
	if (ptr->ev_term) {
		evuser_del(ptr->ev_term);
		event_free(ptr->ev_term);
	}
	if (ptr->mtasks) {
		pgs_list_free(ptr->mtasks);
	}
	if (ptr->control_server)
		pgs_control_server_ctx_destroy(ptr->control_server);
	if (ptr->base)
		event_base_free(ptr->base);
	free(ptr);
}

void *pgs_helper_thread_start(void *data)
{
	pgs_helper_thread_ctx_t *ctx = (pgs_helper_thread_ctx_t *)data;

	pgs_helper_thread_t *helper = pgs_helper_thread_new(
		ctx->cfd, ctx->config, ctx->logger, ctx->sm, ctx->ssl_ctx);

	*ctx->helper_ref = helper;

	// timer for logger
	pgs_timer_t *t1 = pgs_timer_init(1, pgs_timer_cb, helper);

	// timer for connect and g204, interval can be setted by config
	pgs_timer_t *t2 = pgs_timer_init(1, pgs_metrics_timer_cb, helper);

	event_base_dispatch(helper->base);

	pgs_timer_destroy(t2);

	pgs_timer_destroy(t1);

	// drain logs
	pgs_logger_tryrecv(helper->logger, helper->config->log_file);

	pgs_helper_thread_free(helper);

	free(ctx);

	return 0;
}
