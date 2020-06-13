#include "crm_local_server.h"
#include "crm_socks5.h"
#include <stdlib.h>

static void accept_error_cb(crm_listener_t *listener, void *ctx)
{
	struct event_base *base = evconnlistener_get_base(listener);
	int err = EVUTIL_SOCKET_ERROR();

	fprintf(stderr,
		"Got an error %d (%s) on the listener."
		"Shutting down \n",
		err, evutil_socket_error_to_string(err));

	event_base_loopexit(base, NULL);
}

static void new_conn_read_cb(struct bufferevent *bev, void *ctx)
{
	// Socks5 local
	// Then choose server type
	struct evbuffer *output = bufferevent_get_output(bev);
	struct evbuffer *input = bufferevent_get_input(bev);

	crm_local_server_t *local = (crm_local_server_t *)ctx;

	// read from local
	// TODO: add conn {rbuf, wbuf}, add socks5 state_machine, then pass to tls
	// check step machine, and write response

	// set write buffer
	// evbuffer_add(output, data, strlen(data));
}

static void new_conn_event_cb(struct bufferevent *bev, short events, void *ctx)
{
	if (events & BEV_EVENT_ERROR)
		perror("Error from bufferevent");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR))
		bufferevent_free(bev);
}

static void accept_conn_cb(crm_listener_t *listener, crm_socket_t fd,
			   crm_sockaddr_t *address, int socklen, void *ctx)
{
	// new connection, setup a bufferevent for it
	struct event_base *base = evconnlistener_get_base(listener);
	struct bufferevent *bev = bufferevent_socket_new(base, fd, 0);

	// after socks5 end, pass fd to remains
	bufferevent_setcb(bev, new_conn_read_cb, NULL, new_conn_event_cb, ctx);
	bufferevent_enable(bev, EV_READ | EV_WRITE);
}

// New server
crm_local_server_t *crm_local_server_new(crm_socket_t sfd)
{
	crm_local_server_t *ptr = malloc(sizeof(crm_local_server_t));

	ptr->base = event_base_new();

	ptr->listener =
		evconnlistener_new(ptr->base, accept_conn_cb, ptr,
				   LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
				   -1, sfd);

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

