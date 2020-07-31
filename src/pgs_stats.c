#include "pgs_stats.h"
#include "pgs_core.h"

static void time_cb(evutil_socket_t fd, short event, void *arg)
{
	pgs_stats_time_cb_arg_t *ctx = arg;
	// try to read metrics
	pgs_server_manager_tryrecv(ctx->server->sm);
	pgs_evtimer_add(ctx->ev, &ctx->tv);
}

pgs_stats_server_t *pgs_stats_server_new(pgs_server_manager_t *sm,
					 pgs_logger_t *logger,
					 const pgs_config_t *config)
{
	pgs_stats_server_t *ptr = pgs_malloc(sizeof(pgs_stats_server_t));
	ptr->tid = (pgs_tid)pthread_self();
	ptr->base = pgs_ev_base_new();

	ptr->sm = sm;
	ptr->logger = logger;
	ptr->config = config;

	return ptr;
}

void pgs_stats_server_free(pgs_stats_server_t *ptr)
{
	if (ptr->base)
		pgs_ev_base_free(ptr->base);
	if (ptr->logger)
		pgs_logger_free(ptr->logger);
	pgs_free(ptr);
}

void pgs_stats_server_start(pgs_stats_server_t *ptr)
{
	struct timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 0;

	pgs_event_t *ev;

	pgs_stats_time_cb_arg_t arg = { ptr, ev, tv };
	ev = pgs_evtimer_new(ptr->base, time_cb, (void *)&arg);
	arg.ev = ev;

	pgs_evtimer_add(ev, &tv);

	pgs_ev_base_dispatch(ptr->base);
}

void *start_stats_server(void *data)
{
	pgs_stats_server_ctx_t *ctx = (pgs_stats_server_ctx_t *)data;

	pgs_logger_t *logger = pgs_logger_new(ctx->mpsc, ctx->config->log_level,
					      ctx->config->log_isatty);

	pgs_stats_server_t *stats_server =
		pgs_stats_server_new(ctx->sm, logger, ctx->config);

	pgs_stats_server_start(stats_server);

	pgs_stats_server_free(stats_server);
	return 0;
}
