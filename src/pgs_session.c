#include "pgs_codec.h"
#include "pgs_crypto.h"
#include "pgs_defs.h"
#include "pgs_session.h"
#include "pgs_server_manager.h"
#include "pgs_log.h"

#include <unistd.h>
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <event2/bufferevent_ssl.h>

/*
 * local handlers
 */
static void on_local_event(struct bufferevent *bev, short events, void *ctx);
static void on_local_read(struct bufferevent *bev, void *ctx);

/*
 * trojan session handlers
 */
static void on_trojan_remote_event(struct bufferevent *bev, short events,
				   void *ctx);
static void on_trojan_remote_read(struct bufferevent *bev, void *ctx);
static void on_trojan_local_read(struct bufferevent *bev, void *ctx);
static void do_trojan_local_write(uint8_t *msg, uint64_t len,
				  pgs_session_t *session);
static void do_trojan_remote_write(uint8_t *msg, uint64_t len,
				   pgs_session_t *session);

/*
 * v2ray session handlers
 */
static void on_v2ray_remote_event(struct bufferevent *bev, short events,
				  void *ctx);
static void on_v2ray_remote_read(struct bufferevent *bev, void *ctx);
static void on_v2ray_local_read(struct bufferevent *bev, void *ctx);
static void do_v2ray_ws_local_write(struct bufferevent *bev, void *ctx);

/*
 * metrics
 */
static void on_session_metrics_recv(pgs_session_t *session, uint64_t len);
static void on_session_metrics_send(pgs_session_t *session, uint64_t len);

/*
 * udp
  */
static int init_udp_fd(const pgs_config_t *config, int *fd, int *port);
static int start_udp_server(const pgs_server_config_t *sconfig,
			    pgs_session_t *session, int *port);
//static void on_udp_read_v2ray_tcp(int fd, short event, void *ctx);
//static void on_udp_read_v2ray_ws(int fd, short event, void *ctx);
//static void on_udp_read_trojan_ws(int fd, short event, void *ctx);
static void on_udp_read_trojan_gfw(int fd, short event, void *ctx);

static int init_udp_fd(const pgs_config_t *config, int *fd, int *port)
{
	int err = 0;
	struct sockaddr_in sin = { 0 };

	memset(&sin, 0, sizeof(sin));

	sin.sin_family = AF_INET;
	err = inet_pton(AF_INET, config->local_address, &sin.sin_addr);
	if (err <= 0) {
		if (err == 0)
			pgs_config_error(config, "Not in presentation format");
		else
			perror("inet_pton");
		return err;
	}

	*fd = socket(AF_INET, SOCK_DGRAM, 0);

	int flag = fcntl(*fd, F_GETFL, 0);
	fcntl(*fd, F_SETFL, flag | O_NONBLOCK);

	err = bind(*fd, (struct sockaddr *)&sin, sizeof(sin));

	socklen_t size = sizeof(sin);
	getsockname(*fd, (struct sockaddr *)&sin, &size);

	if (err < 0) {
		perror("bind");
		return err;
	}
	*port = ntohs(sin.sin_port);
	return err;
}

/*
 * Create UDP server for UDP ASSOCIATE
 * Returns error
 * Session should close the server fd and free the udp event when error occurred
 * */
static int start_udp_server(const pgs_server_config_t *config,
			    pgs_session_t *session, int *port)
{
	int err = init_udp_fd(session->local_server->config,
			      &session->inbound->udp_fd, port);
	if (err != 0 || port == 0) {
		// error
		pgs_session_error(session, "failed to init udp server");
		return err;
	}
	session->inbound->udp_rbuf = (uint8_t *)malloc(BUFSIZE_16K);
	session->inbound->udp_remote_wbuf = (uint8_t *)malloc(BUFSIZE_16K);

	if (strcmp(config->server_type, "trojan") == 0) {
		pgs_trojanserver_config_t *trojanconf =
			(pgs_trojanserver_config_t *)config->extra;
		if (trojanconf->websocket.enabled) {
			// trojan-go
			session->inbound->udp_server_ev =
				event_new(session->local_server->base,
					  session->inbound->udp_fd,
					  EV_READ | EV_PERSIST,
					  on_udp_read_trojan_gfw, session);
			event_add(session->inbound->udp_server_ev, NULL);
			return 0;
		} else {
			// trojan-gfw
			session->inbound->udp_server_ev =
				event_new(session->local_server->base,
					  session->inbound->udp_fd,
					  EV_READ | EV_PERSIST,
					  on_udp_read_trojan_gfw, session);
			event_add(session->inbound->udp_server_ev, NULL);
			return 0;
		}
	} else if (strcmp(config->server_type, "v2ray") == 0) {
		pgs_v2rayserver_config_t *vconf = config->extra;
		if (!vconf->websocket.enabled) {
			// raw tcp vmess
			session->inbound->udp_server_ev =
				event_new(session->local_server->base,
					  session->inbound->udp_fd,
					  EV_READ | EV_PERSIST,
					  on_udp_read_trojan_gfw, session);
			event_add(session->inbound->udp_server_ev, NULL);
			return 0;
		} else {
			// websocket can be protected by ssl
			session->inbound->udp_server_ev =
				event_new(session->local_server->base,
					  session->inbound->udp_fd,
					  EV_READ | EV_PERSIST,
					  on_udp_read_trojan_gfw, session);
			event_add(session->inbound->udp_server_ev, NULL);
			return 0;
		}
	}
	pgs_session_error(
		session,
		"failed to init udp server: server type(%s) not supported",
		config->server_type);
	// server type not supported
	return -1;
}

/**
 * Create New Sesson
 *
 * @param fd the local socket fd
 * @param local_address the local_server object
 *  which contains logger, base, etc..
 * @return a pointer of new session
 */
pgs_session_t *pgs_session_new(int fd, pgs_local_server_t *local_server)
{
	pgs_session_t *ptr = malloc(sizeof(pgs_session_t));

	struct bufferevent *bev = bufferevent_socket_new(local_server->base, fd,
							 BEV_OPT_CLOSE_ON_FREE);
	ptr->inbound = pgs_session_inbound_new(bev);

	ptr->outbound = NULL;

	// init metrics
	ptr->metrics = malloc(sizeof(pgs_server_session_stats_t));
	ptr->metrics->start = time(NULL);
	ptr->metrics->end = time(NULL);
	ptr->metrics->recv = 0;
	ptr->metrics->send = 0;

	ptr->local_server = local_server;

	return ptr;
}

/**
 * Start session
 *
 * it will set event callbacks for local socket fd
 * then enable READ event
 */
void pgs_session_start(pgs_session_t *session)
{
	// new connection, setup a bufferevent for it
	struct bufferevent *bev = session->inbound->bev;

	bufferevent_setcb(bev, on_local_read, NULL, on_local_event, session);
	bufferevent_enable(bev, EV_READ);
}

void pgs_session_free(pgs_session_t *session)
{
	if (session->inbound)
		pgs_session_inbound_free(session->inbound);

	if (session->outbound) {
		session->metrics->end = time(NULL);
		const char *addr = session->outbound->dest;
		// emit metrics
		pgs_session_stats_msg_t *msg = pgs_session_stats_msg_new(
			session->metrics->start, session->metrics->end,
			session->metrics->send, session->metrics->recv,
			session->outbound->config_idx);
		pgs_session_stats_msg_send(msg, session->local_server->sm);
		pgs_session_info(
			session,
			"connection to %s:%d closed, send: %d, recv: %d", addr,
			session->outbound->port, session->metrics->send,
			session->metrics->recv);
		pgs_session_outbound_free(session->outbound);
	}

	if (session->metrics)
		free(session->metrics);

	free(session);
}

pgs_session_inbound_t *pgs_session_inbound_new(struct bufferevent *bev)
{
	pgs_session_inbound_t *ptr = malloc(sizeof(pgs_session_inbound_t));
	ptr->bev = bev;
	ptr->state = INBOUND_AUTH;
	ptr->cmd = NULL;
	ptr->cmdlen = 0;
	ptr->udp_fd = -1;
	ptr->udp_client_addr = (struct sockaddr_in){ 0 };
	ptr->udp_client_addr_size = sizeof(struct sockaddr);
	ptr->udp_server_ev = NULL;
	ptr->udp_rbuf = NULL;
	ptr->udp_remote_wbuf = NULL;
	ptr->udp_remote_wbuf_pos = 0;
	return ptr;
}

void pgs_session_inbound_free(pgs_session_inbound_t *ptr)
{
	if (ptr->bev != NULL) {
		bufferevent_free(ptr->bev);
		ptr->bev = NULL;
	}
	if (ptr->cmd != NULL) {
		free(ptr->cmd);
		ptr->cmd = NULL;
	}
	if (ptr->udp_fd != -1) {
		close(ptr->udp_fd);
		ptr->udp_fd = -1;
	}
	if (ptr->udp_server_ev != NULL) {
		event_free(ptr->udp_server_ev);
	}
	if (ptr->udp_rbuf != NULL) {
		free(ptr->udp_rbuf);
		ptr->udp_rbuf = NULL;
	}
	if (ptr->udp_remote_wbuf != NULL) {
		free(ptr->udp_remote_wbuf);
		ptr->udp_remote_wbuf = NULL;
	}
	free(ptr);
}

void pgs_session_inbound_update(const pgs_server_config_t *config,
				pgs_logger_t *logger, struct bufferevent *inbev,
				pgs_session_inbound_cbs_t inbound_cbs,
				void *cb_ctx)
{
	if (strcmp(config->server_type, "trojan") == 0) {
		pgs_trojanserver_config_t *trojanconf =
			(pgs_trojanserver_config_t *)config->extra;
		if (trojanconf->websocket.enabled) {
			if (inbev && inbound_cbs.on_local_event &&
			    inbound_cbs.on_trojan_ws_local_read)
				bufferevent_setcb(
					inbev,
					inbound_cbs.on_trojan_ws_local_read,
					NULL, inbound_cbs.on_local_event,
					cb_ctx);
		} else {
			// trojan-gfw
			if (inbev && inbound_cbs.on_local_event &&
			    inbound_cbs.on_trojan_gfw_local_read)
				bufferevent_setcb(
					inbev,
					inbound_cbs.on_trojan_gfw_local_read,
					NULL, inbound_cbs.on_local_event,
					cb_ctx);
		}
	} else if (strcmp(config->server_type, "v2ray") == 0) {
		pgs_v2rayserver_config_t *vconf = config->extra;
		if (!vconf->websocket.enabled) {
			// raw tcp vmess
			if (inbev && inbound_cbs.on_local_event &&
			    inbound_cbs.on_v2ray_tcp_local_read)
				bufferevent_setcb(
					inbev,
					inbound_cbs.on_v2ray_tcp_local_read,
					NULL, inbound_cbs.on_local_event,
					cb_ctx);
		} else {
			// websocket can be protected by ssl
			if (inbev && inbound_cbs.on_local_event &&
			    inbound_cbs.on_v2ray_ws_local_read)
				bufferevent_setcb(
					inbev,
					inbound_cbs.on_v2ray_ws_local_read,
					NULL, inbound_cbs.on_local_event,
					cb_ctx);
		}
	}
}

/**
 * inbound event handler
 */
static void on_local_event(struct bufferevent *bev, short events, void *ctx)
{
	// free buffer event and related session
	pgs_session_t *session = (pgs_session_t *)ctx;
	if (events & BEV_EVENT_ERROR)
		pgs_session_error(session,
				  "Error from bufferevent: on_local_event");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		bufferevent_free(bev);
		pgs_session_free(session);
	}
}

/*
 * inbound on read handler
 * socks5 handshake -> proxy
 */
static void on_local_read(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "local tcp read triggered");

	pgs_session_inbound_state state = session->inbound->state;

	struct evbuffer *output = bufferevent_get_output(bev);
	struct evbuffer *input = bufferevent_get_input(bev);

	uint64_t len = evbuffer_get_length(input);
	unsigned char *rdata = evbuffer_pullup(input, len);

	// pgs_session_debug_buffer(session, rdata, len);

	switch (state) {
	case INBOUND_AUTH:
		if (len < 2 || rdata[0] != 0x5) {
			pgs_session_error(session, "socks5: auth");
			goto error;
		}
		evbuffer_add(output, "\x05\x00", 2);
		evbuffer_drain(input, len);
		session->inbound->state = INBOUND_CMD;
		return;
	case INBOUND_CMD: {
		if (len < 7 || rdata[0] != 0x5 || rdata[2] != 0x0) {
			pgs_session_error(session, "socks5: cmd");
			goto error;
		}
		// parse cmd first
		uint8_t atype = rdata[3];
		// uint16_t port = rdata[len - 2] << 8 | rdata[len - 1];
		int addr_len = 0;
		switch (atype) {
		case 0x01:
			// IPv4
			addr_len = 4;
			break;
		case 0x03:
			// Domain
			addr_len = rdata[4] + 1;
			break;
		case 0x04:
			// IPv6
			addr_len = 16;
			break;
		default:
			pgs_session_error(session, "socks5: wrong atyp");
			goto error;
		}
		// cache cmd
		session->inbound->cmdlen = 4 + addr_len + 2;
		session->inbound->cmd =
			malloc(sizeof(uint8_t) * session->inbound->cmdlen);
		memcpy(session->inbound->cmd, rdata, session->inbound->cmdlen);

		// handle different commands
		// get current server index
		pgs_server_config_t *config = pgs_server_manager_get_config(
			session->local_server->sm);
		int config_idx = -1;
		for (int i = 0;
		     i < session->local_server->config->servers_count; i++) {
			if (config ==
			    &session->local_server->config->servers[i]) {
				config_idx = i;
				break;
			}
		}
		switch (rdata[1]) {
		case 0x01: {
			// CMD connect
			// socks5 response, BND.ADDR and BND.PORT should be 0
			// only the UDP ASSOCIATE command will set this,
			// otherwise it may cause some kind of error,
			// e.g. using `nc -X 5 -x 127.0.0.1:1080 %h %p` to proxy the ssh connection
			evbuffer_add(output,
				     "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00",
				     10);
			evbuffer_drain(input, session->inbound->cmdlen);

			const uint8_t *cmd = session->inbound->cmd;
			uint64_t cmd_len = session->inbound->cmdlen;

			pgs_session_inbound_cbs_t inbound_cbs = {
				on_local_event, on_trojan_local_read,
				on_trojan_local_read, on_v2ray_local_read,
				on_v2ray_local_read
			};
			pgs_session_outbound_cbs_t outbound_cbs = {
				on_trojan_remote_event, on_trojan_remote_event,
				on_v2ray_remote_event,	on_v2ray_remote_event,
				on_trojan_remote_read,	on_trojan_remote_read,
				on_v2ray_remote_read,	on_v2ray_remote_read
			};
			// create outbound
			session->outbound = pgs_session_outbound_new(
				config, config_idx, cmd, cmd_len,
				session->local_server->logger,
				session->local_server->base,
				session->local_server->dns_base, outbound_cbs,
				session);
			// update inbound cbs
			pgs_session_inbound_update(
				config, session->local_server->logger, bev,
				inbound_cbs, session);

			if (session && session->outbound) {
				const char *addr = session->outbound->dest;
				pgs_session_info(session, "--> %s:%d", addr,
						 session->outbound->port);
			}
			session->inbound->state = INBOUND_PROXY;
			return;
		}
		case 0x02: // TODO: bind
		case 0x03: {
			// CMD UDP ASSCOTIATE
			int port = 0;
			int err = start_udp_server(config, session, &port);
			if (err != 0 || port == 0) {
				goto error;
			}
			pgs_session_info(session, "udp server listening at: %d",
					 port);
			// create outbound and setup callbacks
			const uint8_t *cmd = session->inbound->cmd;
			uint64_t cmd_len = session->inbound->cmdlen;

			pgs_session_outbound_cbs_t outbound_cbs = {
				on_trojan_remote_event, on_trojan_remote_event,
				on_v2ray_remote_event,	on_v2ray_remote_event,
				on_trojan_remote_read,	on_trojan_remote_read,
				on_v2ray_remote_read,	on_v2ray_remote_read
			};
			// create outbound
			session->outbound = pgs_session_outbound_new(
				config, config_idx, cmd, cmd_len,
				session->local_server->logger,
				session->local_server->base,
				session->local_server->dns_base, outbound_cbs,
				session);
			// FIXME: hardcoded ATYP and BND.ADDR
			evbuffer_add(output, "\x05\x00\x00\x01\x00\x00\x00\x00",
				     8);
			int ns_port = htons(port);
			evbuffer_add(output, &ns_port, 2);
			evbuffer_drain(input, len);
			session->inbound->state = INBOUND_UDP_RELAY;
			return;
		}
		default:
			pgs_session_error(session,
					  "socks5: cmd not support yet");
			goto error;
		}
	}
	default:
		break;
	}
	return;
error:
	pgs_session_free(session);
}

/**
 * outound event handler
 */
static void on_trojan_remote_event(struct bufferevent *bev, short events,
				   void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;

	if (events & BEV_EVENT_CONNECTED) {
		pgs_session_t *session = (pgs_session_t *)ctx;
		const pgs_server_config_t *config = session->outbound->config;
		const pgs_trojanserver_config_t *trojanconfig = config->extra;
		if (trojanconfig->websocket.enabled) {
			// ws conenct
			pgs_session_debug(session,
					  "do_trojan_ws_remote_request");
			pgs_ws_req(
				bufferevent_get_output(session->outbound->bev),
				trojanconfig->websocket.hostname,
				config->server_address, config->server_port,
				trojanconfig->websocket.path);
			pgs_session_debug(session,
					  "do_trojan_ws_remote_request done");
		} else {
			// trojan-gfw
			// should trigger a local read manually
			pgs_session_debug(session, "trojan-gfw connected");
			pgs_trojansession_ctx_t *trojan_s_ctx =
				session->outbound->ctx;
			trojan_s_ctx->connected = true;
			// manually trigger a read local event
			if (session->inbound->state == INBOUND_PROXY) {
				// TCP
				on_trojan_local_read(session->inbound->bev,
						     ctx);
			} else if (session->inbound->state ==
					   INBOUND_UDP_RELAY &&
				   session->inbound->udp_remote_wbuf != NULL &&
				   session->inbound->udp_remote_wbuf_pos > 0) {
				// UDP
				do_trojan_remote_write(
					session->inbound->udp_remote_wbuf,
					session->inbound->udp_remote_wbuf_pos,
					session);
				session->inbound->udp_remote_wbuf_pos = 0;
			}
		}
	}
	if (events & BEV_EVENT_ERROR)
		pgs_session_error(
			session,
			"Error from bufferevent: on_trojan_remote_event");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		SSL *ssl = bufferevent_openssl_get_ssl(bev);
		if (ssl)
			pgs_ssl_close(ssl);
		bufferevent_free(bev);

		pgs_session_free(session);
	}
}

/*
 * outound read handler
 * it will handle websocket upgrade or 
 * remote -> decode(ws frame) -> local
 */
static void on_trojan_remote_read(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "remote read triggered");
	struct evbuffer *output = bufferevent_get_output(bev);
	struct evbuffer *input = bufferevent_get_input(bev);

	uint64_t data_len = evbuffer_get_length(input);
	unsigned char *data = evbuffer_pullup(input, data_len);

	const pgs_server_config_t *config = session->outbound->config;
	if (config == NULL) {
		pgs_session_error(session, "current server config not found");
		goto error;
	}
	pgs_trojanserver_config_t *trojanconf =
		(pgs_trojanserver_config_t *)config->extra;
	if (!trojanconf->websocket.enabled) {
		// trojan-gfw
		do_trojan_local_write(data, data_len, session);
		evbuffer_drain(input, data_len);
		return;
	}
	// trojan ws
	pgs_trojansession_ctx_t *trojan_s_ctx = session->outbound->ctx;
	if (!trojan_s_ctx->connected) {
		if (!strstr((const char *)data, "\r\n\r\n"))
			return;

		if (pgs_ws_upgrade_check((const char *)data)) {
			pgs_session_error(session, "websocket upgrade fail!");
			on_trojan_remote_event(bev, BEV_EVENT_ERROR, ctx);
		} else {
			//drain
			evbuffer_drain(input, data_len);
			trojan_s_ctx->connected = true;
			// local buffer should have data already
			// manually trigger a read local event
			if (session->inbound->state == INBOUND_PROXY) {
				on_trojan_local_read(bev, ctx);
			} else if (session->inbound->state ==
					   INBOUND_UDP_RELAY &&
				   session->inbound->udp_remote_wbuf != NULL &&
				   session->inbound->udp_remote_wbuf_pos > 0) {
				// should have data in cache already
				do_trojan_remote_write(
					session->inbound->udp_remote_wbuf,
					session->inbound->udp_remote_wbuf_pos,
					session);
				session->inbound->udp_remote_wbuf_pos = 0;
			}
		}
	} else {
		// upgraded, decode it and write to local
		// read from remote
		pgs_session_debug(session, "remote -> decode -> local");

		if (data_len < 2)
			return; // wait next read

		while (data_len > 2) {
			pgs_ws_resp_t ws_meta;
			if (pgs_ws_parse_head(data, data_len, &ws_meta)) {
				// ignore opcode here
				if (ws_meta.opcode == 0x01) {
					// write to local
					do_trojan_local_write(
						data + ws_meta.header_len,
						ws_meta.payload_len, session);
				}

				if (!ws_meta.fin)
					pgs_session_debug(
						session,
						"frame to be continued..");

				evbuffer_drain(input,
					       ws_meta.header_len +
						       ws_meta.payload_len);

				on_session_metrics_recv(
					session, ws_meta.header_len +
							 ws_meta.payload_len);

				data_len -= (ws_meta.header_len +
					     ws_meta.payload_len);
				data += (ws_meta.header_len +
					 ws_meta.payload_len);
			} else {
				pgs_session_warn(
					session,
					"Failed to parse ws header, wait for more data");

				return;
			}
		}
	}
	return;

error:
	pgs_session_free(session);
}

/*
 * inbound read handler
 * it will be enanled after upgraded
 * local -> encode(ws frame) -> remote
 * */
static void on_trojan_local_read(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "local read triggered");

	pgs_trojansession_ctx_t *trojan_s_ctx = session->outbound->ctx;
	if (!trojan_s_ctx->connected)
		return;

	struct evbuffer *inboundr = bufferevent_get_input(bev);
	uint64_t len = evbuffer_get_length(inboundr);
	uint8_t *msg = evbuffer_pullup(inboundr, len);
	pgs_session_debug(session, "local -> encode -> remote");
	struct bufferevent *outbev = session->outbound->bev;
	struct evbuffer *outboundw = bufferevent_get_output(outbev);
	struct evbuffer *wbuf = outboundw;

	const pgs_server_config_t *config = session->outbound->config;
	if (config == NULL) {
		pgs_session_error(session, "current server config not found");
		goto error;
	}
	pgs_trojanserver_config_t *trojanconf =
		(pgs_trojanserver_config_t *)config->extra;
	if (trojanconf->websocket.enabled) {
		//ws
		uint64_t head_len = trojan_s_ctx->head_len;
		uint64_t ws_len = len;
		if (head_len > 0) {
			ws_len += head_len;
		}
		// we only need to write ws header
		// use all 0 for xor encode
		// x ^ 0 = x, so no need for extra xor
		pgs_ws_write_head_text(wbuf, ws_len);
	}

	do_trojan_remote_write(msg, len, session);

	evbuffer_drain(inboundr, len);

	return;

error:
	pgs_session_free(session);
}

/*
 * helper method to write data
 * from local to remote
 * local -> remote
 * */
static void do_trojan_remote_write(uint8_t *msg, uint64_t len,
				   pgs_session_t *session)
{
	struct bufferevent *outbev = session->outbound->bev;
	struct evbuffer *outboundw = bufferevent_get_output(outbev);
	struct evbuffer *buf = outboundw;
	pgs_trojansession_ctx_t *trojan_s_ctx = session->outbound->ctx;
	uint64_t head_len = trojan_s_ctx->head_len;
	if (head_len > 0) {
		evbuffer_add(buf, trojan_s_ctx->head, head_len);
		trojan_s_ctx->head_len = 0;
	}
	evbuffer_add(buf, msg, len);

	pgs_session_debug(session, "local -> remote: %d", len + head_len);
	on_session_metrics_send(session, len + head_len);
}

/*
 * helper method to write data
 * remote -> local
 * */
static void do_trojan_local_write(uint8_t *msg, uint64_t len,
				  pgs_session_t *session)
{
	uint8_t *udp_packet = NULL;
	if (session->inbound->state == INBOUND_PROXY) {
		struct bufferevent *inbev = session->inbound->bev;
		struct evbuffer *inboundw = bufferevent_get_output(inbev);
		evbuffer_add(inboundw, msg, len);
		pgs_session_debug(session, "remote -> local: %d", len);
		on_session_metrics_recv(session, len);
	} else if (session->inbound->state == INBOUND_UDP_RELAY &&
		   session->inbound->udp_fd != -1) {
		uint8_t atype = msg[0];
		uint16_t addr_len = 1 + 2; // atype + port
		switch (atype) {
		case 0x01: { /*ipv4*/
			addr_len += 4;
			break;
		}
		case 0x03: { /*domain*/
			addr_len += 1;
			addr_len += msg[1];
		}
		case 0x04: { /*ipv6*/
			addr_len += 16;
		}
		default:
			break;
		}
		uint16_t payload_len = msg[addr_len] << 8 | msg[addr_len + 1];
		if (len < (addr_len + 2 + 2 + payload_len) ||
		    msg[addr_len + 2] != '\r' || msg[addr_len + 3] != '\n') {
			pgs_session_error(
				session,
				"payload too large or invalid response");
			goto error;
		}
		uint16_t udp_packet_len = 2 + 1 + addr_len + payload_len;
		udp_packet = malloc(udp_packet_len);
		if (udp_packet == NULL) {
			pgs_session_error(session, "out of memory");
			goto error;
		}
		udp_packet[0] = 0x00;
		udp_packet[1] = 0x00;
		udp_packet[2] = 0x00;
		memcpy(udp_packet + 3, msg, addr_len);
		memcpy(udp_packet + 3 + addr_len, msg + addr_len + 4,
		       payload_len);
		int n = sendto(
			session->inbound->udp_fd, udp_packet, udp_packet_len, 0,
			(struct sockaddr *)&session->inbound->udp_client_addr,
			session->inbound->udp_client_addr_size);
		pgs_session_debug(session, "write %d bytes to local udp sock",
				  n);
		free(udp_packet);
	}
	return;

error:
	if (udp_packet != NULL) {
		free(udp_packet);
		udp_packet = NULL;
	}
	pgs_session_free(session);
}

/*
 * v2ray wss session handlers
 */
static void on_v2ray_remote_event(struct bufferevent *bev, short events,
				  void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;

	if (events & BEV_EVENT_CONNECTED) {
		const pgs_server_config_t *config = session->outbound->config;
		const pgs_v2rayserver_config_t *vconfig = config->extra;
		if (vconfig->websocket.enabled) {
			pgs_session_debug(session,
					  "do_v2ray_ws_remote_request");

			pgs_ws_req(
				bufferevent_get_output(session->outbound->bev),
				vconfig->websocket.hostname,
				config->server_address, config->server_port,
				vconfig->websocket.path);

			pgs_session_debug(session,
					  "do_v2ray_ws_remote_request done");
		} else {
			pgs_vmess_ctx_t *v2ray_s_ctx = session->outbound->ctx;
			v2ray_s_ctx->connected = true;
			pgs_session_debug(session, "connected");
			on_v2ray_local_read(session->inbound->bev, ctx);
		}
	}
	if (events & BEV_EVENT_ERROR)
		pgs_session_error(
			session,
			"Error from bufferevent: on_v2ray_remote_event");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		SSL *ssl = bufferevent_openssl_get_ssl(bev);
		if (ssl)
			pgs_ssl_close(ssl);
		bufferevent_free(bev);

		pgs_session_free(session);
	}
}
static void on_v2ray_remote_read(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "remote read triggered");
	const pgs_server_config_t *config = session->outbound->config;
	const pgs_v2rayserver_config_t *vconfig = config->extra;

	struct evbuffer *output = bufferevent_get_output(bev);
	struct evbuffer *input = bufferevent_get_input(bev);

	uint64_t data_len = evbuffer_get_length(input);
	unsigned char *data = evbuffer_pullup(input, data_len);

	pgs_vmess_ctx_t *v2ray_s_ctx = session->outbound->ctx;

	if (!vconfig->websocket.enabled) {
		struct bufferevent *inbev = session->inbound->bev;
		struct evbuffer *inboundw = bufferevent_get_output(inbev);

		if (!pgs_vmess_parse(data, data_len, v2ray_s_ctx, session,
				     (pgs_session_write_fn)v2ray_write_local)) {
			pgs_session_error(session,
					  "failed to decode vmess payload");
			on_v2ray_remote_event(bev, BEV_EVENT_ERROR, ctx);
			return;
		}
		evbuffer_drain(input, data_len);
		on_session_metrics_recv(session, data_len);
		return;
	}
	// ws
	if (!v2ray_s_ctx->connected) {
		if (!strstr((const char *)data, "\r\n\r\n"))
			return;

		if (pgs_ws_upgrade_check((const char *)data)) {
			pgs_session_error(session, "websocket upgrade fail!");
			on_v2ray_remote_event(bev, BEV_EVENT_ERROR, ctx);
		} else {
			//drain
			evbuffer_drain(input, data_len);
			v2ray_s_ctx->connected = true;
			// local buffer should have data already
			// trigger a read manually
			on_v2ray_local_read(bev, ctx);
		}
	} else {
		do_v2ray_ws_local_write(bev, ctx);
	}
}

static void on_v2ray_local_read(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "local read triggered");
	pgs_vmess_ctx_t *v2ray_s_ctx = session->outbound->ctx;
	if (!v2ray_s_ctx->connected)
		return;

	pgs_session_debug(session, "write to remote");
	struct bufferevent *inbev = session->inbound->bev;
	struct bufferevent *outbev = session->outbound->bev;

	struct evbuffer *outboundw = bufferevent_get_output(outbev);
	struct evbuffer *inboundr = bufferevent_get_input(inbev);
	uint64_t data_len = evbuffer_get_length(inboundr);
	if (data_len <= 0)
		return;
	const uint8_t *data = evbuffer_pullup(inboundr, data_len);
	uint64_t total_len = pgs_vmess_write(
		(const uint8_t *)session->outbound->config->password, data,
		data_len, v2ray_s_ctx, session,
		(pgs_session_write_fn)&v2ray_write_out /*this will handle ws encode*/);

	evbuffer_drain(inboundr, data_len);
	on_session_metrics_send(session, total_len);
}

static void do_v2ray_ws_local_write(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session,
			  "do_v2ray_ws_local_write remote -> decode -> local");
	struct bufferevent *inbev = session->inbound->bev;
	struct bufferevent *outbev = session->outbound->bev;

	struct evbuffer *outboundr = bufferevent_get_input(outbev);
	struct evbuffer *inboundw = bufferevent_get_output(inbev);

	uint64_t data_len = evbuffer_get_length(outboundr);
	if (data_len < 2)
		return;

	unsigned char *data = evbuffer_pullup(outboundr, data_len);

	while (data_len > 2) {
		pgs_ws_resp_t ws_meta;
		if (pgs_ws_parse_head(data, data_len, &ws_meta)) {
			pgs_session_debug(
				session,
				"ws_meta.header_len: %d, ws_meta.payload_len: %d, opcode: %d",
				ws_meta.header_len, ws_meta.payload_len,
				ws_meta.opcode);
			// ignore opcode here
			if (ws_meta.opcode == 0x02) {
				// decode vmess protocol
				pgs_vmess_ctx_t *v2ray_s_ctx =
					session->outbound->ctx;
				// TODO: write function
				if (!pgs_vmess_parse(
					    data + ws_meta.header_len,
					    ws_meta.payload_len, v2ray_s_ctx,
					    session,
					    (pgs_session_write_fn)
						    v2ray_write_local)) {
					pgs_session_error(
						session,
						"failed to decode vmess payload");
					on_v2ray_remote_event(
						bev, BEV_EVENT_ERROR, ctx);
					return;
				}
			}

			if (!ws_meta.fin)
				pgs_session_debug(session,
						  "frame to be continue..");

			evbuffer_drain(outboundr, ws_meta.header_len +
							  ws_meta.payload_len);

			on_session_metrics_recv(session,
						ws_meta.header_len +
							ws_meta.payload_len);

			data_len -= (ws_meta.header_len + ws_meta.payload_len);
			data += (ws_meta.header_len + ws_meta.payload_len);

		} else {
			// error parsing websocket data
			return;
		}
	}
}

static void on_session_metrics_recv(pgs_session_t *session, uint64_t len)
{
	if (!session->metrics)
		return;
	session->metrics->recv += len;
}

static void on_session_metrics_send(pgs_session_t *session, uint64_t len)
{
	if (!session->metrics)
		return;
	session->metrics->send += len;
}

/*
 * udp relay
 * */
static void on_udp_read_trojan_gfw(int fd, short event, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "udp local read triggered");

	uint8_t *buf = session->inbound->udp_rbuf;
	socklen_t *size = &session->inbound->udp_client_addr_size;
	struct sockaddr_in *client_addr = &session->inbound->udp_client_addr;
	uint8_t *packet = NULL;

	ssize_t len = recvfrom(fd, buf, BUFSIZE_16K, 0,
			       (struct sockaddr *)client_addr, size);
	if (0 == len) {
		pgs_session_warn(session, "udp connection closed");
	} else if (len > 0) { /*Max read/cache buffer size is 16K*/
		// pgs_session_debug_buffer(session, buf, len);
		if (len <= 3) { /*FRAG is not supported now*/
			pgs_session_error(session, "invalid udp datagram");
			goto error;
		}
		uint16_t addr_len = 1 + 2; // atype + port
		uint8_t atype = buf[3];
		switch (atype) {
		case 0x01: { /*ipv4*/
			addr_len += 4;
			break;
		}
		case 0x03: { /*domain*/
			addr_len += 1;
			addr_len += buf[4];
		}
		case 0x04: { /*ipv6*/
			addr_len += 16;
		}
		default:
			break;
		}
		if (len <= (2 + 1 + addr_len)) {
			pgs_session_error(session, "invalid udp datagram");
			goto error;
		}
		uint16_t data_len = len - 2 - 1 -
				    addr_len; /*RSV(2) | FRAG(1) | ADDR | DATA*/
		uint16_t packet_len =
			addr_len + 2 + 2 +
			data_len; /*ADDR | LEN(2) | CRLF(2) | PAYLOAD(datalen)*/
		packet = (uint8_t *)malloc(packet_len);
		if (packet == NULL) {
			pgs_session_error(session, "out of memory");
			goto error;
		}
		memcpy(packet, buf + 3, addr_len);
		packet[addr_len] = data_len >> 8;
		packet[addr_len + 1] = data_len & 0xFF;
		packet[addr_len + 2] = '\r';
		packet[addr_len + 3] = '\n';
		memcpy(packet + addr_len + 4, buf + 3 + addr_len, data_len);

		// build packet then cache or send it
		pgs_trojansession_ctx_t *trojan_s_ctx = session->outbound->ctx;
		if (!trojan_s_ctx->connected) {
			// Cache this, send it later
			int pos = session->inbound->udp_remote_wbuf_pos;
			if (pos + packet_len >= BUFSIZE_16K) {
				pgs_session_error(session,
						  "udp payload too large");
				goto error;
			}
			memcpy(session->inbound->udp_remote_wbuf + pos, packet,
			       packet_len);
			session->inbound->udp_remote_wbuf_pos += packet_len;
		} else {
			// Send data
			do_trojan_remote_write(packet, packet_len, session);
		}
		if (packet != NULL) {
			free(packet);
			packet = NULL;
		}
	}
	return;

error:
	if (packet != NULL) {
		free(packet);
		packet = NULL;
	}
	pgs_session_free(session);
}
