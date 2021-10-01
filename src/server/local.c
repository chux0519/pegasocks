#include "server/local.h"
#include "session/session.h"

#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

static void accept_error_cb(struct evconnlistener *listener, void *ctx)
{
	pgs_local_server_t *local = (pgs_local_server_t *)ctx;

	struct event_base *base = local->base;
	int err = EVUTIL_SOCKET_ERROR();

	pgs_logger_debug(local->logger,
			 "Got an error %d (%s) on the listener."
			 "Shutting down \n",
			 err, evutil_socket_error_to_string(err));

	// after loop exit, outter process have to free the local_server
	event_base_loopexit(base, NULL);
}

static void accept_conn_cb(struct evconnlistener *listener, int fd,
			   struct sockaddr *address, int socklen, void *ctx)
{
	pgs_local_server_t *local = (pgs_local_server_t *)ctx;
	struct sockaddr_in *sin = (struct sockaddr_in *)address;
	char *ip = inet_ntoa(sin->sin_addr);

	pgs_logger_debug(local->logger, "new client from port %s:%d", ip,
			 sin->sin_port);

	// new session
	pgs_session_t *session = pgs_session_new(fd, local);

	// cache this
	pgs_list_add(local->sessions, session->node);

	// start session
	pgs_session_start(session);
}

/*
 * New server, this must be called in a seperate thread
 * it will create a base loop without LOCK, so not thread-safe (one loop per thread)
 * */
pgs_local_server_t *pgs_local_server_new(int fd, pgs_mpsc_t *mpsc,
					 pgs_config_t *config, pgs_acl_t *acl,
					 pgs_server_manager_t *sm,
					 pgs_ssl_ctx_t *ssl_ctx)
{
	pgs_local_server_t *ptr = malloc(sizeof(pgs_local_server_t));

	ptr->logger =
		pgs_logger_new(mpsc, config->log_level, config->log_isatty);

	ptr->tid = (uint32_t)pthread_self();
	struct event_config *cfg = event_config_new();
	event_config_set_flag(cfg, EVENT_BASE_FLAG_NOLOCK);
	ptr->base = event_base_new_with_config(cfg);
	event_config_free(cfg);

	ptr->dns_base =
		evdns_base_new(ptr->base, EVDNS_BASE_INITIALIZE_NAMESERVERS);
	evdns_base_set_option(ptr->dns_base, "max-probe-timeout:", "5");
	evdns_base_set_option(ptr->dns_base, "probe-backoff-factor:", "1");

	ptr->sessions = pgs_list_new();
	ptr->sessions->free = (void *)pgs_session_free;

	// shared across server threads
	ptr->server_fd = fd;
	ptr->config = config;
	ptr->sm = sm;
	ptr->acl = acl;
	ptr->ssl_ctx = ssl_ctx;

	// server
	ptr->listener =
		evconnlistener_new(ptr->base, accept_conn_cb, ptr,
				   LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
				   -1, fd);
	evconnlistener_set_error_cb(ptr->listener, accept_error_cb);

	return ptr;
}

void pgs_local_server_stop(pgs_local_server_t *local, int timeout)
{
	event_base_loopbreak(local->base);
}

// Destroy local server
void pgs_local_server_destroy(pgs_local_server_t *local)
{
	if (local->listener)
		evconnlistener_free(local->listener);
	if (local->dns_base)
		evdns_base_free(local->dns_base, 0);
	if (local->base)
		event_base_free(local->base);
	if (local->logger)
		pgs_logger_free(local->logger);
	free(local);
}

/*
 * Start new local server
 * One Local Server Per Thread
 * */
void *start_local_server(void *data)
{
	// pgs_local_server_new(&ctx);
	pgs_local_server_ctx_t *ctx = (pgs_local_server_ctx_t *)data;

	pgs_local_server_t *local =
		pgs_local_server_new(ctx->fd, ctx->mpsc, ctx->config, ctx->acl,
				     ctx->sm, ctx->ssl_ctx);

	// it will be used to stop/free pegas from other threads
	*ctx->local_server_ref = local;

	pgs_logger_info(local->logger, "Listening at %s:%d",
			local->config->local_address,
			local->config->local_port);

	event_base_dispatch(local->base);

	// free all pending/active sessions
	pgs_list_free(local->sessions);

	printf("server thread destroy\n");

	pgs_local_server_destroy(local);

	free(ctx);

	printf("server thread exit\n");

	return 0;
}
