#include "pgs_local_server.h"
#include "pgs_session.h"
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>

static void accept_error_cb(pgs_listener_t *listener, void *ctx)
{
	pgs_local_server_t *local = (pgs_local_server_t *)ctx;

	struct event_base *base = local->base;
	int err = PGS_EVUTIL_SOCKET_ERROR();

	pgs_logger_debug(local->logger,
			 "Got an error %d (%s) on the listener."
			 "Shutting down \n",
			 err, pgs_evutil_socket_error_to_string(err));

	// after loop exit, outter process have to free the local_server
	pgs_ev_base_loopexit(base, NULL);
}

static void accept_conn_cb(pgs_listener_t *listener, pgs_socket_t fd,
			   pgs_sockaddr_t *address, int socklen, void *ctx)
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
	ptr->tid = (pgs_tid)pthread_self();
	ptr->logger = pgs_logger_new(ctx->mpsc, ctx->config->log_level,
				     ctx->config->log_isatty);
	ptr->base = pgs_ev_base_new();
	ptr->dns_base = pgs_ev_dns_base_new(ptr->base,
					    EVDNS_BASE_INITIALIZE_NAMESERVERS);
	ptr->config = ctx->config;
	ptr->sm = ctx->sm;
	ptr->listener =
		pgs_listener_new(ptr->base, accept_conn_cb, ptr,
				 LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
				 ctx->fd);
	pgs_listener_set_error_cb(ptr->listener, accept_error_cb);

	return ptr;
}

// Run the Loop
void pgs_local_server_run(pgs_local_server_t *local)
{
	signal(SIGPIPE, SIG_IGN);
	pgs_ev_base_dispatch(local->base);
}

// Destroy local server
void pgs_local_server_destroy(pgs_local_server_t *local)
{
	pgs_listener_free(local->listener);
	pgs_ev_base_free(local->base);
	pgs_ev_dns_base_free(local->dns_base, 0);
	pgs_logger_free(local->logger);
	pgs_free(local);
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
