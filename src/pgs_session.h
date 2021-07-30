#ifndef _PGS_SESSION
#define _PGS_SESSION

#include "pgs_local_server.h"
#include "pgs_outbound.h"
#include <event2/event.h>

#define pgs_session_debug(session, ...)                                        \
	pgs_logger_debug(session->local_server->logger, __VA_ARGS__)
#define pgs_session_info(session, ...)                                         \
	pgs_logger_info(session->local_server->logger, __VA_ARGS__)
#define pgs_session_warn(session, ...)                                         \
	pgs_logger_warn(session->local_server->logger, __VA_ARGS__)
#define pgs_session_error(session, ...)                                        \
	pgs_logger_error(session->local_server->logger, __VA_ARGS__)
#define pgs_session_debug_buffer(session, buf, len)                            \
	pgs_logger_debug_buffer(session->local_server->logger, buf, len)

typedef enum {
	INBOUND_AUTH,
	INBOUND_CMD,
	INBOUND_PROXY,
	INBOUND_UDP_RELAY,
	INBOUND_ERR
} pgs_session_inbound_state;
typedef void(free_ctx_fn)(void *ctx);

typedef struct pgs_session_inbound_s {
	struct bufferevent *bev;
	pgs_session_inbound_state state;
	uint8_t *cmd; /*socks5 cmd*/

	// udp server and event for udp relay
	int udp_fd;
	struct sockaddr_in udp_client_addr;
	socklen_t udp_client_addr_size;
	struct event *udp_server_ev;
	uint8_t *udp_rbuf;
	uint8_t *udp_remote_wbuf;
	uint16_t udp_remote_wbuf_pos;
} pgs_session_inbound_t;

typedef struct pgs_session_s {
	pgs_session_inbound_t *inbound;
	pgs_session_outbound_t *outbound;
	pgs_local_server_t *local_server;
	pgs_server_session_stats_t *metrics;
} pgs_session_t;

typedef struct pgs_session_inbound_cbs_s {
	on_event_cb *on_local_event;
	on_read_cb *on_trojan_ws_local_read;
	on_read_cb *on_trojan_gfw_local_read;
	on_read_cb *on_v2ray_ws_local_read;
	on_read_cb *on_v2ray_tcp_local_read;
} pgs_session_inbound_cbs_t;

// inbound
pgs_session_inbound_t *pgs_session_inbound_new(struct bufferevent *bev);
void pgs_session_inbound_free(pgs_session_inbound_t *sb);

// session
pgs_session_t *pgs_session_new(int fd, pgs_local_server_t *local_server);
void pgs_session_free(pgs_session_t *session);
void pgs_session_start(pgs_session_t *session);

#endif
