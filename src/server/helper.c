#include "server/helper.h"
// #include "server/metrics.h"
#include "session/session.h"
#include "server/control.h"
#include "dns.h"

#include "utils.h"
#include <assert.h>
#include <signal.h>
#include <pthread.h>

#include <event2/event.h>

static void pgs_timer_cb(evutil_socket_t fd, short event, void *data)
{
	pgs_timer_t *arg = data;
	pgs_helper_thread_t *ctx = arg->ctx;
	assert(ctx->fake_local.logger != NULL);
	assert(ctx->fake_local.config != NULL);
	assert(ctx->fake_local.config->log_file != NULL);
	pgs_logger_tryrecv(ctx->fake_local.logger,
			   ctx->fake_local.config->log_file);
	arg->tv.tv_sec = 1;
	arg->tv.tv_usec = 0;
	evtimer_add(arg->ev, &arg->tv);
	return;
}

static void pgs_metrics_timer_cb(evutil_socket_t fd, short event, void *data)
{
	pgs_timer_t *arg = data;
	pgs_helper_thread_t *ctx = arg->ctx;
	for (int i = 0; i < ctx->fake_local.sm->server_len; i++) {
		const pgs_server_config_t *server =
			&ctx->fake_local.config->servers[i];
		pgs_ping_session_new(&ctx->fake_local, server, i);
	}
	arg->tv.tv_sec = ctx->fake_local.config->ping_interval;
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
	pgs_dns_init(ptr->base, &ptr->dns_base, config, logger);

	ptr->fake_local.base = ptr->base;
	ptr->fake_local.config = config;
	ptr->fake_local.acl = NULL;
	ptr->fake_local.dns_base = ptr->dns_base;
	ptr->fake_local.logger = logger;
	ptr->fake_local.sm = sm;
	ptr->fake_local.ssl_ctx = ssl_ctx;
	ptr->fake_local.tid = (uint32_t)pthread_self();
	ptr->fake_local.sessions = pgs_list_new();
	ptr->fake_local.sessions->free = (void *)pgs_ping_session_free;

	event_config_free(cfg);

	// timer for logger
	ptr->log_timer = pgs_timer_init(1, pgs_timer_cb, ptr);

	// timer for connect and g204, interval can be setted by config
	ptr->ping_timer = pgs_timer_init(1, pgs_metrics_timer_cb, ptr);

	ptr->ev_term = evuser_new(ptr->base, pgs_helper_term, ptr->base);

	ptr->tid = (uint32_t)pthread_self();

	return ptr;
}

void pgs_helper_thread_free(pgs_helper_thread_t *ptr)
{
	if (ptr->ev_term) {
		evuser_del(ptr->ev_term);
		event_free(ptr->ev_term);
	}
	if (ptr->fake_local.sessions) {
		pgs_list_free(ptr->fake_local.sessions);
	}
	if (ptr->ping_timer)
		pgs_timer_destroy(ptr->ping_timer);
	if (ptr->log_timer) {
		// drain logs first
		pgs_logger_tryrecv(ptr->fake_local.logger,
				   ptr->fake_local.config->log_file);
		pgs_timer_destroy(ptr->log_timer);
	}
	if (ptr->dns_base)
		evdns_base_free(ptr->dns_base, 0);
	if (ptr->base)
		event_base_free(ptr->base);
	free(ptr);
}

void pgs_helper_ping_remote(pgs_helper_thread_t *helper)
{
	if (helper->ping_timer) {
		pgs_timer_destroy(helper->ping_timer);
	}
	helper->ping_timer = pgs_timer_init(0, pgs_metrics_timer_cb, helper);
}

void *pgs_helper_thread_start(void *data)
{
	pgs_helper_thread_ctx_t *ctx = (pgs_helper_thread_ctx_t *)data;

	pgs_helper_thread_t *helper = pgs_helper_thread_new(
		ctx->cfd, ctx->config, ctx->logger, ctx->sm, ctx->ssl_ctx);

	*ctx->helper_ref = helper;

	pgs_control_server_ctx_t *control_server =
		pgs_control_server_start(ctx->cfd, helper->base, ctx->sm,
					 ctx->logger, ctx->config, helper);

	event_base_dispatch(helper->base);

	pgs_control_server_ctx_destroy(control_server);

	pgs_helper_thread_free(helper);

	free(ctx);

	return 0;
}
