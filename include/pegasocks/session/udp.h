#ifndef _PGS_UDP_H
#define _PGS_UDP_H

#include "defs.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <event2/event.h>

typedef struct pgs_udp_relay_s {
	int udp_fd;
	uint8_t *udp_rbuf;
	struct sockaddr_in udp_server_addr;
	struct event *udp_client_ev;
	struct timeval timeout;

	// packet header
	uint8_t *packet_header;
	int packet_header_len;

	// pointer of session pointer
	void **session_ptr;
} pgs_udp_relay_t;

static pgs_udp_relay_t *pgs_udp_relay_new()
{
	pgs_udp_relay_t *ptr = malloc(sizeof(pgs_udp_relay_t));
	ptr->udp_fd = 0;
	ptr->udp_rbuf = malloc(BUFSIZE_16K * sizeof(uint8_t));
	ptr->udp_client_ev = NULL;
	evutil_timerclear(&ptr->timeout);
	ptr->timeout.tv_sec = 60;
	ptr->session_ptr = malloc(sizeof(void *));

	ptr->packet_header = NULL;
	memzero(&ptr->udp_server_addr, sizeof(struct sockaddr_in));

	return ptr;
}

static void pgs_udp_relay_set_header(pgs_udp_relay_t *ptr, const uint8_t *cmd,
				     int len)
{
	ptr->packet_header_len = len;
	ptr->packet_header = malloc(len);
	memcpy(ptr->packet_header, cmd, len);
}

static int pgs_udp_relay_trigger(pgs_udp_relay_t *ptr, const char *host,
				 short port, uint8_t *buf, ssize_t len,
				 struct event_base *base,
				 on_udp_read_cb *read_cb, void *session)
{
	ptr->udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
	int flag = fcntl(ptr->udp_fd, F_GETFL, 0);
	fcntl(ptr->udp_fd, F_SETFL, flag | O_NONBLOCK);

	*ptr->session_ptr = session;

	ptr->udp_client_ev = event_new(base, ptr->udp_fd, EV_READ | EV_TIMEOUT,
				       read_cb, ptr);

	event_add(ptr->udp_client_ev, &ptr->timeout);

	ptr->udp_server_addr.sin_family = AF_INET;
	int err = inet_pton(AF_INET, host, &ptr->udp_server_addr.sin_addr);
	ptr->udp_server_addr.sin_port = htons(port);
	if (err <= 0) {
		return err;
	}
	ssize_t n = sendto(ptr->udp_fd, buf, len, 0,
			   (struct sockaddr *)&ptr->udp_server_addr,
			   sizeof(ptr->udp_server_addr));
	return n;
}

static void pgs_udp_relay_free(pgs_udp_relay_t *ptr)
{
	if (ptr->udp_fd)
		close(ptr->udp_fd);
	if (ptr->udp_rbuf != NULL)
		free(ptr->udp_rbuf);
	if (ptr->udp_client_ev != NULL)
		event_free(ptr->udp_client_ev);
	if (ptr->packet_header != NULL)
		free(ptr->packet_header);
	if (ptr->session_ptr)
		free(ptr->session_ptr);
	if (ptr != NULL)
		free(ptr);
}

#endif
