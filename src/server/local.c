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
	// start session
	pgs_session_start(session);
}

// New server
pgs_local_server_t *pgs_local_server_new(pgs_local_server_ctx_t *ctx)
{
	pgs_local_server_t *ptr = malloc(sizeof(pgs_local_server_t));
	ptr->logger = pgs_logger_new(ctx->mpsc, ctx->config->log_level,
				     ctx->config->log_isatty);

	ptr->server_fd = ctx->fd;
	ptr->config = ctx->config;
	ptr->sm = ctx->sm;
	ptr->acl = ctx->acl;
	ptr->ssl_ctx = ctx->ssl_ctx;
	assert(ptr->ssl_ctx != NULL);

	return ptr;
}

void pgs_local_server_stop(pgs_local_server_t *local, int timeout)
{
	struct timeval tv;
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	event_base_loopexit(local->base, &tv);
}

// Destroy local server
void pgs_local_server_destroy(pgs_local_server_t *local)
{
	if (local->listener)
		evconnlistener_free(local->listener);
	if (local->base)
		event_base_free(local->base);
	if (local->dns_base)
		evdns_base_free(local->dns_base, 0);
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
	pgs_local_server_t *local = (pgs_local_server_t *)data;
	local->tid = (uint32_t)pthread_self();
	local->logger->tid = (uint32_t)pthread_self();
	struct event_config *cfg = event_config_new();
	event_config_set_flag(cfg, EVENT_BASE_FLAG_NOLOCK);
	local->base = event_base_new_with_config(cfg);
	event_config_free(cfg);

	local->dns_base =
		evdns_base_new(local->base, EVDNS_BASE_INITIALIZE_NAMESERVERS);
	evdns_base_set_option(local->dns_base, "max-probe-timeout:", "5");
	evdns_base_set_option(local->dns_base, "probe-backoff-factor:", "1");

	local->listener =
		evconnlistener_new(local->base, accept_conn_cb, local,
				   LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
				   -1, local->server_fd);
	evconnlistener_set_error_cb(local->listener, accept_error_cb);

	pgs_logger_info(local->logger, "Listening at %s:%d",
			local->config->local_address,
			local->config->local_port);

	// will block here
	event_base_dispatch(local->base);

	//evconnlistener_free(local->listener);
	//evdns_base_free(local->dns_base, 0);
	//event_base_free(local->base);
	//local->dns_base = NULL;
	//local->base = NULL;

	printf("server thread exit\n");

	return 0;
}
