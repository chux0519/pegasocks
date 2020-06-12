#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <time.h>

#include <arpa/inet.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

static void debug(char *data, size_t len)
{
	for (int i = 0; i < len; i++) {
		fprintf(stderr, "%02x  ", (int)data[i]);
	}
}

static void hello_read_cb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *output = bufferevent_get_output(bev);

	char data[512] =
		"HTTP/1.1 200 OK\r\nServer: A\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n";

	time_t now = time(0);
	struct tm tm = *gmtime(&now);
	strftime(data + strlen(data), sizeof data,
		 "Date: %a, %d %b %Y %H:%M:%S %Z\r\n\n", &tm);

	strcat(data, "Hello, World!");

	evbuffer_add(output, data, strlen(data));
}

static void hello_event_cb(struct bufferevent *bev, short events, void *ctx)
{
	if (events & BEV_EVENT_ERROR)
		perror("Error from bufferevent");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR))
		bufferevent_free(bev);
}

static void accept_conn_cb(struct evconnlistener *listener, evutil_socket_t fd,
			   struct sockaddr *address, int socklen, void *ctx)
{
	// new connection, setup a bufferevent for it
	struct event_base *base = evconnlistener_get_base(listener);
	struct bufferevent *bev =
		bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);

	bufferevent_setcb(bev, hello_read_cb, NULL, hello_event_cb, NULL);
	bufferevent_enable(bev, EV_READ | EV_WRITE);
}

static void accept_error_cb(struct evconnlistener *listener, void *ctx)
{
	struct event_base *base = evconnlistener_get_base(listener);
	int err = EVUTIL_SOCKET_ERROR();

	fprintf(stderr,
		"Got an error %d (%s) on the listener."
		"Shutting down \n",
		err, evutil_socket_error_to_string(err));

	event_base_loopexit(base, NULL);
}

int main(int argc, char **argv)
{
	struct event_base *base;
	struct evconnlistener *listener;
	struct sockaddr_in sin;

	int port = 8080;

	if (argc > 1)
		port = atoi(argv[1]);

	base = event_base_new();

	memset(&sin, 0, sizeof(sin));

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0); // 0.0.0.0
	sin.sin_port = htons(port);

	listener = evconnlistener_new_bind(
		base, accept_conn_cb, NULL,
		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
		(struct sockaddr *)&sin, sizeof(sin));

	evconnlistener_set_error_cb(listener, accept_error_cb);
	event_base_dispatch(base);

	return 0;
}

