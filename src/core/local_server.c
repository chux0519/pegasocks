#include "core/local_server.h"
#include "core/session.h"

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
	ptr->tid = (uint32_t)pthread_self();
	ptr->logger = pgs_logger_new(ctx->mpsc, ctx->config->log_level,
				     ctx->config->log_isatty);
	ptr->base = event_base_new();

	ptr->dns_base =
		evdns_base_new(ptr->base, EVDNS_BASE_INITIALIZE_NAMESERVERS);
	evdns_base_set_option(ptr->dns_base, "max-probe-timeout:", "5");
	evdns_base_set_option(ptr->dns_base, "probe-backoff-factor:", "1");

	ptr->config = ctx->config;
	ptr->sm = ctx->sm;
	ptr->acl = ctx->acl;
	ptr->ssl_ctx = ctx->ssl_ctx;
	assert(ptr->ssl_ctx != NULL);
	ptr->listener =
		evconnlistener_new(ptr->base, accept_conn_cb, ptr,
				   LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
				   -1, ctx->fd);
	evconnlistener_set_error_cb(ptr->listener, accept_error_cb);

	return ptr;
}

// Run the Loop
void pgs_local_server_run(pgs_local_server_t *local)
{
	// event_add(local->udp_event, NULL);
	event_base_dispatch(local->base);
}

// Destroy local server
void pgs_local_server_destroy(pgs_local_server_t *local)
{
	evconnlistener_free(local->listener);
	event_base_free(local->base);
	evdns_base_free(local->dns_base, 0);
	pgs_logger_free(local->logger);
	free(local);
}

/*
 * Start new local server
 * One Local Server Per Thread
 * */
void *start_local_server(void *data)
{
	pgs_local_server_ctx_t *ctx = (pgs_local_server_ctx_t *)data;
	pgs_local_server_t *local = pgs_local_server_new(ctx);

	pgs_logger_info(local->logger, "Listening at %s:%d",
			local->config->local_address,
			local->config->local_port);

	// will block here
	pgs_local_server_run(local);

	// Destroy here
	// After loop exit
	pgs_local_server_destroy(local);

	return 0;
}
