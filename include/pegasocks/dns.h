#ifndef _PGS_SERVER_DNS_H
#define _PGS_SERVER_DNS_H

#include "config.h"

#include <event2/dns.h>

#ifdef __ANDROID__
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int pgs_protect_fd(int fd, const char *protect_address, int protect_port)
{
	int sock;
	struct sockaddr_in addr = { 0 };
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1)
		return -1;

	struct timeval tv;
	tv.tv_sec = 3;
	tv.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,
		   sizeof(struct timeval));
	setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv,
		   sizeof(struct timeval));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(protect_port);
	if (inet_pton(AF_INET, protect_address, &(addr.sin_addr)) != 1) {
		close(sock);
		return -1;
	}

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		close(sock);
		return -1;
	}

	char buf[4] = { 0 };
	buf[0] = (fd >> 24) & 0xFF;
	buf[1] = (fd >> 16) & 0xFF;
	buf[2] = (fd >> 8) & 0xFF;
	buf[3] = fd & 0xFF;
	int n = write(sock, buf, 4);
	if (n != 4) {
		close(sock);
		return -1;
	}

	n = read(sock, buf, 4);
	if (n != 4) {
		close(sock);
		return -1;
	}
	close(sock);

	int ret = buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
	if (ret != fd) {
		return -1;
	}
	return fd;
}
#endif

static void pgs_dns_init(struct event_base *base,
			 struct evdns_base **dns_base_ptr, pgs_config_t *config,
			 pgs_logger_t *logger)
{
	if ((config)->dns_servers->len > 0) {
		*(dns_base_ptr) = evdns_base_new((base), 0);
		pgs_list_node_t *cur, *next;
		pgs_list_foreach((config)->dns_servers, cur, next)
		{
			pgs_logger_debug((logger), "Add DNS server: %s",
					 (const char *)cur->val);
			if (evdns_base_nameserver_ip_add(
				    *(dns_base_ptr), (const char *)cur->val) !=
			    0)
				pgs_logger_error((logger),
						 "Failed to add DNS server: %s",
						 (const char *)cur->val);
		}
	} else {
#ifdef __ANDROID__
		*(dns_base_ptr) = evdns_base_new((base), 0);
#else
		*(dns_base_ptr) = evdns_base_new(
			(base), EVDNS_BASE_INITIALIZE_NAMESERVERS);
#endif
	}
	evdns_base_set_option(*(dns_base_ptr), "max-probe-timeout:", "5");
	evdns_base_set_option(*(dns_base_ptr), "probe-backoff-factor:", "1");

#ifdef __ANDROID__
	int count = evdns_base_count_nameservers(*(dns_base_ptr));
	for (int i = 0; i < count; ++i) {
		int fd = evdns_base_get_nameserver_fd(*(dns_base_ptr), i);
		if (fd > 0) {
			int ret =
				pgs_protect_fd(fd,
					       config->android_protect_address,
					       config->android_protect_port);
			if (ret != fd) {
				pgs_logger_error(
					logger,
					"Failed to protect nameserver's fd");
			} else {
				pgs_logger_info(logger,
						"Nameserver's fd protected");
			}
		}
	}
#endif
}

#endif
