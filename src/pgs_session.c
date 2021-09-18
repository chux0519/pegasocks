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

/*
 * local handlers
 */
static void on_local_event(struct bufferevent *bev, short events, void *ctx);
static void on_local_read(struct bufferevent *bev, void *ctx);

/*
 * bypass handlers
 */
static void on_bypass_remote_event(struct bufferevent *bev, short events,
				   void *ctx);
static void on_bypass_remote_read(struct bufferevent *bev, void *ctx);
static void on_bypass_local_read(struct bufferevent *bev, void *ctx);

/*
 * trojan session handlers
 */
static void on_trojan_remote_event(struct bufferevent *bev, short events,
				   void *ctx);
static void on_trojan_remote_read(struct bufferevent *bev, void *ctx);
static void on_trojan_local_read(struct bufferevent *bev, void *ctx);

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

// this determine whether it should be bypassed or not
static void on_udp_read(int fd, short event, void *ctx);
static void on_udp_read_trojan(const uint8_t *buf, ssize_t len,
			       pgs_session_t *session);
static void on_udp_read_v2ray(const uint8_t *buf, ssize_t len,
			      pgs_session_t *session);

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
	session->cur_config = config;
	session->inbound->udp_rbuf = (uint8_t *)malloc(BUFSIZE_16K);
	session->inbound->udp_remote_wbuf = (uint8_t *)malloc(BUFSIZE_16K);
	session->inbound->udp_server_ev =
		event_new(session->local_server->base, session->inbound->udp_fd,
			  EV_READ | EV_PERSIST, on_udp_read, session);
	event_add(session->inbound->udp_server_ev, NULL);
	return 0;
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
	ptr->metrics = malloc(sizeof(pgs_session_stats_t));
	gettimeofday(&ptr->metrics->start, NULL);
	gettimeofday(&ptr->metrics->end, NULL);
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
		gettimeofday(&session->metrics->end, NULL);
		char tm_start_str[32], tm_end_str[32];
		PARSE_SESSION_TIMEVAL(tm_start_str, session->metrics->start);
		PARSE_SESSION_TIMEVAL(tm_end_str, session->metrics->end);
		pgs_session_info(
			session,
			"connection to %s:%d closed, start: %s, end: %s, send: %d, recv: %d",
			session->outbound->dest, session->outbound->port,
			tm_start_str, tm_end_str, session->metrics->send,
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
				bool proxy,
				pgs_session_inbound_cbs_t inbound_cbs,
				void *cb_ctx)
{
	if (proxy) {
		if (strcmp(config->server_type, "trojan") == 0) {
			if (inbev && inbound_cbs.on_local_event &&
			    inbound_cbs.on_trojan_local_read)
				bufferevent_setcb(
					inbev, inbound_cbs.on_trojan_local_read,
					NULL, inbound_cbs.on_local_event,
					cb_ctx);
		} else if (strcmp(config->server_type, "v2ray") == 0) {
			if (inbev && inbound_cbs.on_local_event &&
			    inbound_cbs.on_v2ray_local_read)
				bufferevent_setcb(
					inbev, inbound_cbs.on_v2ray_local_read,
					NULL, inbound_cbs.on_local_event,
					cb_ctx);
		}
	} else {
		if (inbev && inbound_cbs.on_local_event &&
		    inbound_cbs.on_bypass_local_read)
			bufferevent_setcb(inbev,
					  inbound_cbs.on_bypass_local_read,
					  NULL, inbound_cbs.on_local_event,
					  cb_ctx);
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
 * acl checked here
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
		// uint16_t port = rdata[len - 2] << 8 | rdata[len - 1];
		int addr_len = pgs_get_addr_len(rdata + 3);
		if (addr_len == 0) {
			pgs_session_error(session, "socks5: wrong atyp");
			goto error;
		}
		// cache cmd
		uint64_t cmdlen = 4 + addr_len + 2;
		session->inbound->cmd = malloc(sizeof(uint8_t) * cmdlen);
		memcpy(session->inbound->cmd, rdata, cmdlen);

		// handle different commands
		// get current server index
		pgs_server_config_t *config = pgs_server_manager_get_config(
			session->local_server->sm);

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
			evbuffer_drain(input, cmdlen);

			const uint8_t *cmd = session->inbound->cmd;
			pgs_session_inbound_cbs_t inbound_cbs = {
				on_local_event, on_trojan_local_read,
				on_v2ray_local_read, on_bypass_local_read
			};
			pgs_session_outbound_cbs_t outbound_cbs = {
				on_trojan_remote_event,
				on_v2ray_remote_event,
				on_bypass_remote_event,
				on_trojan_remote_read,
				on_v2ray_remote_read,
				on_bypass_remote_read,
				NULL
			};
			bool proxy = true;
			// create outbound
			session->outbound = pgs_session_outbound_new();
			if (!pgs_session_outbound_init(
				    session->outbound, config, cmd, cmdlen,
				    session->local_server->logger,
				    session->local_server->base,
				    session->local_server->dns_base,
				    session->local_server->acl, &proxy,
				    outbound_cbs, session))
				goto error;

			// update inbound cbs
			pgs_session_inbound_update(
				config, session->local_server->logger, bev,
				proxy, inbound_cbs, session);

			if (session && session->outbound) {
				const char *addr = session->outbound->dest;
				pgs_session_info(session, "--> %s:%d", addr,
						 session->outbound->port);
			}
			session->inbound->state = INBOUND_PROXY;
			return;
		}
		case 0x02: // bind
		case 0x03: {
			// CMD UDP ASSOCIATE
			int port = 0;
			// TODO: if bypass, we should set a bypass UDP server?
			int err = start_udp_server(config, session, &port);
			if (err != 0 || port == 0) {
				goto error;
			}
			pgs_session_info(session, "udp server listening at: %d",
					 port);

			bool proxy = true;
			if (proxy) {
				// create outbound and setup callbacks
				const uint8_t *cmd = session->inbound->cmd;

				pgs_session_outbound_cbs_t outbound_cbs = {
					on_trojan_remote_event,
					on_v2ray_remote_event,
					on_bypass_remote_event,
					on_trojan_remote_read,
					on_v2ray_remote_read,
					NULL /* if bypass then need no remote*/,
					NULL
				};

				session->outbound = pgs_session_outbound_new();
				if (!pgs_session_outbound_init(
					    session->outbound, config, cmd,
					    cmdlen,
					    session->local_server->logger,
					    session->local_server->base,
					    session->local_server->dns_base,
					    session->local_server->acl, &proxy,
					    outbound_cbs, session))
					goto error;
			}

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

/*
 * bypass
 */

static void on_bypass_remote_event(struct bufferevent *bev, short events,
				   void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;

	if (events & BEV_EVENT_CONNECTED) {
		on_bypass_local_read(session->inbound->bev, ctx);
	}

	if (events & BEV_EVENT_ERROR)
		pgs_session_error(
			session,
			"Error from bufferevent: on_bypass_remote_event");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		pgs_free_bev_ssl_ctx(bev);
		bufferevent_free(bev);

		pgs_session_free(session);
	}
}

static void on_bypass_local_read(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "local read triggered");

	struct evbuffer *inboundr = bufferevent_get_input(bev);
	uint64_t len = evbuffer_get_length(inboundr);
	uint8_t *msg = evbuffer_pullup(inboundr, len);

	struct bufferevent *outbev = session->outbound->bev;
	struct evbuffer *outboundw = bufferevent_get_output(outbev);

	if (len > 0) {
		evbuffer_add(outboundw, msg, len);
		evbuffer_drain(inboundr, len);
	}
	return;

error:
	pgs_session_free(session);
}

static void on_bypass_remote_read(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "remote read triggered");
	struct evbuffer *input = bufferevent_get_input(bev);
	uint64_t data_len = evbuffer_get_length(input);
	unsigned char *data = evbuffer_pullup(input, data_len);

	if (data_len > 0) {
		struct bufferevent *inbev = session->inbound->bev;
		struct evbuffer *inboundw = bufferevent_get_output(inbev);
		evbuffer_add(inboundw, data, data_len);
		evbuffer_drain(input, data_len);
	}

	return;

error:
	pgs_session_free(session);
}

/*
 * trojan
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
				trojan_write_remote(
					session,
					session->inbound->udp_remote_wbuf,
					session->inbound->udp_remote_wbuf_pos);
				session->inbound->udp_remote_wbuf_pos = 0;
			}
		}
	}
	if (events & BEV_EVENT_ERROR)
		pgs_session_error(
			session,
			"Error from bufferevent: on_trojan_remote_event");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		pgs_free_bev_ssl_ctx(bev);
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
		trojan_write_local(session, data, data_len);
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
				trojan_write_remote(
					session,
					session->inbound->udp_remote_wbuf,
					session->inbound->udp_remote_wbuf_pos);
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
					trojan_write_local(
						session,
						data + ws_meta.header_len,
						ws_meta.payload_len);
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

	trojan_write_remote(session, msg, len);

	evbuffer_drain(inboundr, len);

	return;

error:
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
			if (session->inbound->state == INBOUND_PROXY) {
				// TCP
				on_v2ray_local_read(session->inbound->bev, ctx);
			} else if (session->inbound->state ==
					   INBOUND_UDP_RELAY &&
				   session->inbound->udp_remote_wbuf != NULL &&
				   session->inbound->udp_remote_wbuf_pos > 0) {
				// UDP
				uint64_t total_len = pgs_vmess_write_remote(
					session,
					session->inbound->udp_remote_wbuf,
					session->inbound->udp_remote_wbuf_pos,
					(pgs_session_write_fn)&vmess_flush_remote);

				session->inbound->udp_remote_wbuf_pos = 0;
			}
		}
	}
	if (events & BEV_EVENT_ERROR)
		pgs_session_error(
			session,
			"Error from bufferevent: on_v2ray_remote_event");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		pgs_free_bev_ssl_ctx(bev);
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

		if (!pgs_vmess_parse(session, data, data_len,
				     (pgs_session_write_fn)vmess_flush_local)) {
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
			evbuffer_drain(input, data_len);
			v2ray_s_ctx->connected = true;
			if (session->inbound->state == INBOUND_PROXY) {
				on_v2ray_local_read(bev, ctx);
			} else if (session->inbound->state ==
					   INBOUND_UDP_RELAY &&
				   session->inbound->udp_remote_wbuf != NULL &&
				   session->inbound->udp_remote_wbuf_pos > 0) {
				// UDP
				uint64_t total_len = pgs_vmess_write_remote(
					session,
					session->inbound->udp_remote_wbuf,
					session->inbound->udp_remote_wbuf_pos,
					(pgs_session_write_fn)&vmess_flush_remote);
				session->inbound->udp_remote_wbuf_pos = 0;
			}
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
	uint64_t total_len = pgs_vmess_write_remote(
		session, data, data_len,
		(pgs_session_write_fn)&vmess_flush_remote /*this will handle ws encode*/);

	evbuffer_drain(inboundr, data_len);
	on_session_metrics_send(session, total_len);
}

static void do_v2ray_ws_local_write(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "v2ray remote -> decode -> local");
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
				if (!pgs_vmess_parse(
					    session, data + ws_meta.header_len,
					    ws_meta.payload_len,
					    (pgs_session_write_fn)
						    vmess_flush_local)) {
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

static void on_udp_read(int fd, short event, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "udp local read triggered");
	const pgs_server_config_t *config = session->cur_config;

	uint8_t *buf = session->inbound->udp_rbuf;
	socklen_t *size = &session->inbound->udp_client_addr_size;
	struct sockaddr_in *client_addr = &session->inbound->udp_client_addr;

	char *dest = NULL;
	int port = 0;

	ssize_t len = recvfrom(fd, buf, BUFSIZE_16K, 0,
			       (struct sockaddr *)client_addr, size);
	if (0 == len) {
		pgs_session_warn(session, "udp connection closed");
	} else if (len > 0) { /*Max read/cache buffer size is 16K*/
		if (len <= 3) { /*FRAG is not supported now*/
			pgs_session_error(session, "invalid udp datagram");
			goto error;
		}
		uint8_t atype = buf[3];
		// check if this should bypass
		// if bypass, send it directly, do a udp relay
		// if not send it to outbound via different protocol(trojan/v2ray outbound)
		bool proxy = true;
		socks5_dest_addr_parse(buf, len, session->local_server->acl,
				       &proxy, &dest, &port);

		if (proxy) {
			if (strcmp(config->server_type, "trojan") == 0) {
				if (session->outbound == NULL) {
					// TODO: create outbound
					// session->outbound =
				}
				// will cache data in remote_wbuf before connected
				on_udp_read_trojan(buf, len, session);
			} else if (strcmp(config->server_type, "v2ray") == 0) {
				if (session->outbound == NULL) {
					// TODO: create outbound
					// session->outbound =
				}
				// will cache data in remote_wbuf before connected
				on_udp_read_v2ray(buf, len, session);
			}
			pgs_session_error(
				session,
				"failed to handle udp packet: server type(%s) not supported",
				config->server_type);
		} else {
			pgs_session_info(session, "udp bypass: %s:%d", dest,
					 port);
			// create an udp outbound and write to it
		}
	}

	if (dest != NULL) {
		free(dest);
	}

error:
	if (dest != NULL) {
		free(dest);
	}
	pgs_session_free(session);
}

static void on_udp_read_trojan(const uint8_t *buf, ssize_t len,
			       pgs_session_t *session)
{
	uint8_t *packet = NULL;

	// pgs_session_debug_buffer(session, buf, len);
	if (len <= 3) { /*FRAG is not supported now*/
		pgs_session_error(session, "invalid udp datagram");
		goto error;
	}
	uint16_t addr_len = 1 + 2; // atype + port
	addr_len += pgs_get_addr_len(buf + 3);
	if (len <= (2 + 1 + addr_len)) {
		pgs_session_error(session, "invalid udp datagram");
		goto error;
	}
	uint16_t data_len =
		len - 2 - 1 - addr_len; /*RSV(2) | FRAG(1) | ADDR | DATA*/
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
			pgs_session_error(session, "udp payload too large");
			goto error;
		}
		memcpy(session->inbound->udp_remote_wbuf + pos, packet,
		       packet_len);
		session->inbound->udp_remote_wbuf_pos += packet_len;
	} else {
		// Send data
		trojan_write_remote(session, packet, packet_len);
	}
	if (packet != NULL) {
		free(packet);
		packet = NULL;
	}
	return;

error:
	if (packet != NULL) {
		free(packet);
		packet = NULL;
	}
	pgs_session_free(session);
}

static void on_udp_read_v2ray(const uint8_t *buf, ssize_t len,
			      pgs_session_t *session)
{
	if (len <= 3) { /*FRAG is not supported now*/
		pgs_session_error(session, "invalid udp datagram");
		goto error;
	}

	pgs_vmess_ctx_t *v2ray_s_ctx = session->outbound->ctx;
	// store target_addr
	uint16_t addr_len = 1 + 2; // atype + port
	addr_len += pgs_get_addr_len(buf + 3);
	if (len <= (2 + 1 + addr_len)) {
		pgs_session_error(session, "invalid udp datagram");
		goto error;
	}
	uint16_t data_len =
		len - 2 - 1 - addr_len; /*RSV(2) | FRAG(1) | ADDR | DATA*/

	v2ray_s_ctx->target_addr_len = addr_len;
	memcpy(v2ray_s_ctx->target_addr, buf + 3, addr_len);

	if (!v2ray_s_ctx->connected) {
		// Cache, it will be sent when connected
		memcpy(session->inbound->udp_remote_wbuf +
			       session->inbound->udp_remote_wbuf_pos,
		       buf + 3 + addr_len, data_len);
		session->inbound->udp_remote_wbuf_pos += data_len;
	} else {
		// UDP
		uint64_t total_len = pgs_vmess_write_remote(
			session, buf + 3 + addr_len, data_len,
			(pgs_session_write_fn)&vmess_flush_remote);
		session->inbound->udp_remote_wbuf_pos = 0;
	}
	return;

error:
	pgs_session_free(session);
}
