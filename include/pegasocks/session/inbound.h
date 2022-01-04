#ifndef _PGS_SESSION_INBOUND_H
#define _PGS_SESSION_INBOUND_H

#include "utils.h"

typedef enum {
	INBOUND_AUTH,
	INBOUND_CMD,
	INBOUND_PROXY,
	INBOUND_UDP_RELAY,
	INBOUND_ERR
} pgs_session_inbound_state;

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
	int rbuf_pos;

	// bypass udp sessions
	pgs_list_t *udp_bypass_sessions;
} pgs_session_inbound_t;

pgs_session_inbound_t *pgs_session_inbound_new(struct bufferevent *bev);
void pgs_session_inbound_start(pgs_session_inbound_t *inbound, void *ctx);
void pgs_session_inbound_free(pgs_session_inbound_t *sb);

/* local read handlers 
 * triggered by readable events and
 * when remote server connected
 * */
void on_bypass_local_read(struct bufferevent *bev, void *ctx);
void on_trojan_local_read(struct bufferevent *bev, void *ctx);
void on_v2ray_local_read(struct bufferevent *bev, void *ctx);
void on_ss_local_read(struct bufferevent *bev, void *ctx);

// UDP
void on_udp_read_trojan(const uint8_t *buf, ssize_t len, void *ctx);
void on_udp_read_v2ray(const uint8_t *buf, ssize_t len, void *ctx);
void on_remote_udp_read(int fd, short event, void *ctx);
// TODO: shadowsocks

#endif
