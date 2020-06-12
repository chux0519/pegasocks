#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <time.h>

#include <arpa/inet.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>

#define MAX_THREADS 4

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

void *start_server(void *server_fd)
{
	int sfd = (int)server_fd;

	struct event_base *base;
	struct evconnlistener *listener;

	base = event_base_new();

	listener = evconnlistener_new(base, accept_conn_cb, NULL,
				      LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
				      -1, sfd);

	evconnlistener_set_error_cb(listener, accept_error_cb);
	event_base_dispatch(base);

	evconnlistener_free(listener);
	event_base_free(base);
	pthread_exit(NULL);
}

int main(int argc, char **argv)
{
	int err = 0;
	struct sockaddr_in sin;

	int port = 8080;

	if (argc > 1)
		port = atoi(argv[1]);

	memset(&sin, 0, sizeof(sin));

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0); // 0.0.0.0
	sin.sin_port = htons(port);

	int server_fd = socket(AF_INET, SOCK_STREAM, 0);
	int reuse_port = 1;

	err = setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT,
			 (const void *)&reuse_port, sizeof(int));
	if (err < 0) {
		perror("setsockopt");
		return err;
	}

	int flag = fcntl(server_fd, F_GETFL, 0);
	fcntl(server_fd, F_SETFL, flag | O_NONBLOCK);

	err = bind(server_fd, (struct sockaddr *)&sin, sizeof(sin));

	if (err < 0) {
		perror("bind");
		return err;
	}

	pthread_t threads[MAX_THREADS];
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_setcancelstate(&attr, PTHREAD_CREATE_JOINABLE);

	for (int i = 0; i < MAX_THREADS; i++) {
		pthread_create(&threads[i], &attr, start_server, server_fd);
	}

	for (int i = 0; i < MAX_THREADS; i++) {
		pthread_join(threads[i], NULL);
	}

	pthread_attr_destroy(&attr);

	return 0;
}
