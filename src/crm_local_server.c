#include "crm_local_server.h"
#include "crm_socks5.h"
#include "crm_session.h"
#include <stdlib.h>
#include <pthread.h>

static void accept_error_cb(crm_listener_t *listener, void *ctx)
{
	crm_local_server_t *local = (crm_local_server_t *)ctx;

	struct event_base *base = evconnlistener_get_base(listener);
	int err = EVUTIL_SOCKET_ERROR();

	crm_logger_debug(local->logger,
			 "Got an error %d (%s) on the listener."
			 "Shutting down \n",
			 err, evutil_socket_error_to_string(err))

		// after loop exit, outter process have to free the local_server
		event_base_loopexit(base, NULL);
}

static void accept_conn_cb(crm_listener_t *listener, crm_socket_t fd,
			   crm_sockaddr_t *address, int socklen, void *ctx)
{
	crm_local_server_t *local = (crm_local_server_t *)ctx;
	struct sockaddr_in *sin = (struct sockaddr_in *)address;
	char *ip = inet_ntoa(sin->sin_addr);

	crm_logger_debug(local->logger, "new client from port %s:%d", ip,
			 sin->sin_port);

	// new session
	crm_session_t *session = crm_session_new(fd, local);
	// start session
	crm_session_start(session);
}

// New server
crm_local_server_t *crm_local_server_new(crm_local_server_ctx_t *ctx)

{
	crm_local_server_t *ptr = malloc(sizeof(crm_local_server_t));
	ptr->tid = (crm_tid)pthread_self();
	ptr->logger = crm_logger_new(ctx->mpsc, DEBUG);
	ptr->base = event_base_new();
	ptr->listener =
		evconnlistener_new(ptr->base, accept_conn_cb, ptr,
				   LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
				   -1, ctx->fd);

	evconnlistener_set_error_cb(ptr->listener, accept_error_cb);

	return ptr;
}

// Run the Loop
void crm_local_server_run(crm_local_server_t *local)
{
	event_base_dispatch(local->base);
}

// Destroy local server
void crm_local_server_destroy(crm_local_server_t *local)
{
	evconnlistener_free(local->listener);
	event_base_free(local->base);
	free(local);
}

// Start new local server
// One Local Server Per Thread
void *start_local_server(void *data)
{
	crm_local_server_ctx_t *ctx = (crm_local_server_ctx_t *)data;
	crm_local_server_t *local = crm_local_server_new(ctx);

	crm_logger_debug(local->logger, "hello from logger");

	// will block here
	crm_local_server_run(local);

	// Destroy here
	// After loop exit
	crm_local_server_destroy(local);

	return 0;
}
