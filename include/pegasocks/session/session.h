#ifndef _PGS_SESSION_H
#define _PGS_SESSION_H

#ifndef _WIN32
#include <netinet/in.h>
#endif
#include <event2/event.h>
#include <event2/buffer.h>

#include "server/local.h"
#include "utils.h"

#ifndef htonll
#define htonll(x)                                                              \
	((1 == htonl(1)) ?                                                     \
		       (x) :                                                         \
		       ((uint64_t)htonl((x)&0xFFFFFFFF) << 32) | htonl((x) >> 32))
#endif

#ifndef ntohll
#define ntohll(x) htonll(x)
#endif

#define pgs_session_debug(session, ...)                                        \
	pgs_logger_debug(session->local->logger, __VA_ARGS__)
#define pgs_session_info(session, ...)                                         \
	pgs_logger_info(session->local->logger, __VA_ARGS__)
#define pgs_session_warn(session, ...)                                         \
	pgs_logger_warn(session->local->logger, __VA_ARGS__)
#define pgs_session_error(session, ...)                                        \
	pgs_logger_error(session->local->logger, __VA_ARGS__)
#define pgs_session_debug_buffer(session, buf, len)                            \
	pgs_logger_debug_buffer(session->local->logger, buf, len)
#define PGS_FREE_SESSION(session)                                              \
	pgs_list_del(session->local->sessions, session->node)

typedef enum {
	PROTOCOL_TYPE_TCP = 0x01,
	PROTOCOL_TYPE_UDP = 0x03

	/*
	 The same as socks5 RFC's CMD section
		o  CMD
			o  CONNECT X'01'
			o  UDP ASSOCIATE X'03'
	*/
} pgs_protocol_t;
typedef enum {
	SOCKS5_AUTH = 0,
	SOCKS5_CMD,
	SOCKS5_PROXY,
	SOCKS5_UDP_ASSOCIATE,
	DNS_RESOLVE,
} pgs_socks5_state;

typedef struct pgs_server_session_stats_s {
	struct timeval start;
	struct timeval end;
	uint64_t send;
	uint64_t recv;
} pgs_session_stats_t;

typedef struct pgs_inbound_s {
	pgs_protocol_t protocol;

	void *ctx;

	void (*read)(void *session);
	bool (*write)(void *ctx, uint8_t *msg, size_t len, size_t *olen);
	void (*free)(void *ctx);
} pgs_inbound_t;

typedef struct pgs_outbound_s {
	pgs_protocol_t protocol;
	bool ready;
	void *ctx;

	bool (*write)(void *ctx, uint8_t *msg, size_t len, size_t *olen);
	void (*free)(void *ctx);
} pgs_outbound_t;

typedef struct pgs_trojan_ctx_s {
	int fd;
	struct bufferevent *bev;

	// sha224(password) + "\r\n" + cmd[1] + cmd.substr(3) + "\r\n"
	char *head;
	size_t head_len;
} pgs_trojan_ctx_t;

typedef struct pgs_socks5_cmd_s {
	uint8_t atype;
	char *dest;
	uint16_t port;

	uint8_t *raw_cmd;
	size_t cmd_len;
} pgs_socks5_cmd_t;

typedef struct pgs_udp_ctx_s {
	int fd;
	pgs_buffer_t *cache;
	size_t cache_len;

	struct sockaddr_in in_addr;
	socklen_t in_addr_len;
	const pgs_socks5_cmd_t *cmd;
} pgs_udp_ctx_t;

typedef struct pgs_session_s {
	pgs_socks5_state state;
	bool proxy;
	pgs_socks5_cmd_t cmd;

	const pgs_server_config_t *config;
	pgs_local_server_t *local;

	pgs_inbound_t inbound;
	pgs_outbound_t outbound;

	pgs_list_t *filters; /* filters */

#ifdef WITH_ACL
	struct evdns_request *dns_req;
#endif

	pgs_list_node_t *node; /* store the value to sessions */
} pgs_session_t;

typedef struct pgs_ping_session_s {
	pgs_session_t session; /* session can be up cast to pgs_ping_session_t */

	double ping;
	double g204;

	int idx;

	struct timeval ts_start;
	struct timeval ts_send;
	struct timeval ts_recv;
} pgs_ping_session_t;

pgs_ping_session_t *pgs_ping_session_new(pgs_local_server_t *,
					 const pgs_server_config_t *, int);
void pgs_ping_session_free(pgs_ping_session_t *);

pgs_trojan_ctx_t *pgs_trojan_ctx_new(pgs_session_t *);
void pgs_trojan_ctx_free(pgs_trojan_ctx_t *);

pgs_udp_ctx_t *pgs_udp_ctx_new(int, const pgs_socks5_cmd_t *);

void pgs_udp_ctx_free(pgs_udp_ctx_t *);

// session
pgs_session_t *pgs_session_new(pgs_local_server_t *,
			       const pgs_server_config_t *);
void pgs_session_start_tcp(pgs_session_t *session, int fd);
void pgs_session_start_udp(pgs_session_t *session, int fd);
void pgs_session_free(pgs_session_t *session);

pgs_socks5_cmd_t socks5_cmd_parse(const uint8_t *, size_t);
void pgs_socks5_cmd_free(pgs_socks5_cmd_t);

void on_local_event(struct bufferevent *bev, short events, void *ctx);
void on_socks5_handshake(struct bufferevent *bev, void *ctx);

static inline int socks5_cmd_get_addr_len(const uint8_t *data)
{
	switch (data[0] /*atype*/) {
	case 0x01:
		// IPv4
		return 4;
	case 0x03:
		return 1 + data[1];
	case 0x04:
		// IPv6
		return 16;
	default:
		break;
	}
	return 0;
}

#endif