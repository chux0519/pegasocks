#include "pgs_codec.h"
#include "pgs_crypto.h"
#include "pgs_session.h"
#include "pgs_server_manager.h"
#include "pgs_log.h"

#include <unistd.h>
#include <assert.h>
#include <ctype.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <event2/bufferevent_ssl.h>

/*
 * local handlers
 */
static void on_local_event(struct bufferevent *bev, short events, void *ctx);
static void on_local_read(struct bufferevent *bev, void *ctx);

/*
 * trojan websocket session handler
 */
static void on_trojan_ws_remote_event(struct bufferevent *bev, short events,
				      void *ctx);
static void on_trojan_ws_remote_read(struct bufferevent *bev, void *ctx);
static void on_trojan_ws_local_read(struct bufferevent *bev, void *ctx);
static void do_trojan_ws_remote_request(struct bufferevent *bev, void *ctx);
static void do_trojan_ws_remote_write(struct bufferevent *bev, void *ctx);
static void do_trojan_ws_local_write(struct bufferevent *bev, void *ctx);

/*
 * trojan gfw session handler
 */
static void on_trojan_gfw_remote_event(struct bufferevent *bev, short events,
				       void *ctx);
static void on_trojan_gfw_remote_read(struct bufferevent *bev, void *ctx);
static void on_trojan_gfw_local_read(struct bufferevent *bev, void *ctx);
static void do_trojan_gfw_remote_write(struct bufferevent *bev, void *ctx);
static void do_trojan_gfw_local_write(struct bufferevent *bev, void *ctx);

/*
 * v2ray websocket session handler
 */
static void on_v2ray_ws_remote_event(struct bufferevent *bev, short events,
				     void *ctx);
static void on_v2ray_ws_remote_read(struct bufferevent *bev, void *ctx);
static void on_v2ray_ws_local_read(struct bufferevent *bev, void *ctx);
static void do_v2ray_ws_remote_request(struct bufferevent *bev, void *ctx);
static void do_v2ray_ws_remote_write(struct bufferevent *bev, void *ctx);
static void do_v2ray_ws_local_write(struct bufferevent *bev, void *ctx);
static void v2ray_ws_vmess_write_cb(struct evbuffer *writer, uint8_t *data,
				    uint64_t len);

/*
 * v2ray tcp session handler
 */
static void on_v2ray_tcp_remote_event(struct bufferevent *bev, short events,
				      void *ctx);
static void on_v2ray_tcp_remote_read(struct bufferevent *bev, void *ctx);
static void on_v2ray_tcp_local_read(struct bufferevent *bev, void *ctx);

/*
 * metrics
 */
static void on_session_metrics_recv(pgs_session_t *session, uint64_t len);
static void on_session_metrics_send(pgs_session_t *session, uint64_t len);

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
	return ptr;
}

void pgs_session_inbound_free(pgs_session_inbound_t *ptr)
{
	if (ptr->bev)
		bufferevent_free(ptr->bev);
	if (ptr->cmd)
		free(ptr->cmd);
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
	pgs_session_debug(session, "read triggered");

	if (session->inbound->state >= INBOUND_PROXY) {
		// error
		pgs_session_error(session, "unreachable local read state");
		goto error;
	}

	if (!pgs_socks5_handshake(session)) {
		// error
		pgs_session_error(session, "failed to do socks5 handshake");
		goto error;
	}

	// outbound should reset local read callback
	if (session->inbound->state == INBOUND_PROXY) {
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

		const uint8_t *cmd = session->inbound->cmd;
		uint64_t cmd_len = session->inbound->cmdlen;

		pgs_session_inbound_cbs_t inbound_cbs = {
			on_local_event, on_trojan_ws_local_read,
			on_trojan_gfw_local_read, on_v2ray_ws_local_read,
			on_v2ray_tcp_local_read
		};
		pgs_session_outbound_cbs_t outbound_cbs = {
			on_trojan_ws_remote_event, on_trojan_gfw_remote_event,
			on_v2ray_ws_remote_event,  on_v2ray_tcp_remote_event,
			on_trojan_ws_remote_read,  on_trojan_gfw_remote_read,
			on_v2ray_ws_remote_read,   on_v2ray_tcp_remote_read
		};
		// create outbound
		session->outbound = pgs_session_outbound_new(
			config, config_idx, cmd, cmd_len,
			session->local_server->logger,
			session->local_server->base,
			session->local_server->dns_base, outbound_cbs, session);
		// update inbound cbs
		pgs_session_inbound_update(config,
					   session->local_server->logger, bev,
					   inbound_cbs, session);

		if (session && session->outbound) {
			const char *addr = session->outbound->dest;
			pgs_session_info(session, "--> %s:%d", addr,
					 session->outbound->port);
		}
	}

	return;

error:
	pgs_session_free(session);
}

/**
 * outound event handler
 */
static void on_trojan_ws_remote_event(struct bufferevent *bev, short events,
				      void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;

	if (events & BEV_EVENT_CONNECTED)
		do_trojan_ws_remote_request(bev, ctx);
	if (events & BEV_EVENT_ERROR)
		pgs_session_error(
			session,
			"Error from bufferevent: on_trojan_ws_remote_event");
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
static void on_trojan_ws_remote_read(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "remote read triggered");
	struct evbuffer *output = bufferevent_get_output(bev);
	struct evbuffer *input = bufferevent_get_input(bev);

	uint64_t data_len = evbuffer_get_length(input);
	unsigned char *data = evbuffer_pullup(input, data_len);

	pgs_trojansession_ctx_t *trojan_s_ctx = session->outbound->ctx;
	if (!trojan_s_ctx->connected) {
		if (!strstr((const char *)data, "\r\n\r\n"))
			return;

		if (pgs_ws_upgrade_check((const char *)data)) {
			pgs_session_error(session, "websocket upgrade fail!");
			on_trojan_ws_remote_event(bev, BEV_EVENT_ERROR, ctx);
		} else {
			//drain
			evbuffer_drain(input, data_len);
			trojan_s_ctx->connected = true;
			// local buffer should have data already
			do_trojan_ws_remote_write(bev, ctx);
		}
	} else {
		// upgraded, decode it and write to local
		do_trojan_ws_local_write(bev, ctx);
	}
}

/*
 * inbound read handler
 * it will be enanled after upgraded
 * local -> encode(ws frame) -> remote
 * */
static void on_trojan_ws_local_read(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "local read triggered");

	pgs_trojansession_ctx_t *trojan_s_ctx = session->outbound->ctx;
	if (!trojan_s_ctx->connected)
		return;

	pgs_session_debug(session, "write to remote");
	do_trojan_ws_remote_write(bev, ctx);
}

/*
 * outbound websocket handshake
 * */
static void do_trojan_ws_remote_request(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	const pgs_server_config_t *config = session->outbound->config;
	const pgs_trojanserver_config_t *trojanconfig = config->extra;

	pgs_session_debug(session, "do_trojan_ws_remote_request");

	pgs_ws_req(bufferevent_get_output(session->outbound->bev),
		   trojanconfig->websocket.hostname, config->server_address,
		   config->server_port, trojanconfig->websocket.path);

	pgs_session_debug(session, "do_trojan_ws_remote_request done");
}

/*
 * helper method to write data
 * from local to remote
 * local -> encode(ws frame) -> remote
 * */
static void do_trojan_ws_remote_write(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "local -> encode -> remote");
	struct bufferevent *inbev = session->inbound->bev;
	struct bufferevent *outbev = session->outbound->bev;

	struct evbuffer *outboundw = bufferevent_get_output(outbev);
	struct evbuffer *inboundr = bufferevent_get_input(inbev);

	struct evbuffer *buf = outboundw;
	uint64_t len = evbuffer_get_length(inboundr);
	unsigned char *msg = evbuffer_pullup(inboundr, len);

	pgs_trojansession_ctx_t *trojan_s_ctx = session->outbound->ctx;
	uint64_t head_len = trojan_s_ctx->head_len;
	if (head_len > 0)
		len += head_len;

	pgs_ws_write_head_text(buf, len);

	if (head_len > 0) {
		evbuffer_add(buf, trojan_s_ctx->head, head_len);
		trojan_s_ctx->head_len = 0;
	}
	// x ^ 0 = x
	evbuffer_add(buf, msg, len - head_len);

	evbuffer_drain(inboundr, len - head_len);

	on_session_metrics_send(session, len);
}

/*
 * helper method to write data
 * from remote to local
 * remote -> decode(ws frame) -> local
 * */
static void do_trojan_ws_local_write(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "remote -> decode -> local");
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
			// ignore opcode here
			if (ws_meta.opcode == 0x01) {
				// write to local
				evbuffer_add(inboundw,
					     data + ws_meta.header_len,
					     ws_meta.payload_len);
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
			return;
		}
	}
}

/*
 * trojan gfw event handler
 */
static void on_trojan_gfw_remote_event(struct bufferevent *bev, short events,
				       void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;

	if (events & BEV_EVENT_CONNECTED) {
		pgs_session_debug(session, "connected");
		pgs_trojansession_ctx_t *trojan_s_ctx = session->outbound->ctx;
		trojan_s_ctx->connected = true;
		do_trojan_gfw_remote_write(bev, ctx);
	}
	if (events & BEV_EVENT_ERROR)
		pgs_session_error(
			session,
			"Error from bufferevent: on_trojan_gfw_remote_event");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		SSL *ssl = bufferevent_openssl_get_ssl(bev);
		if (ssl)
			pgs_ssl_close(ssl);
		bufferevent_free(bev);
		pgs_session_error(session, "EOF from remote, free session");
		pgs_session_free(session);
	}
}

/*
 * outound read handler
 * it will handle websocket upgrade or 
 * remote -> local
 */
static void on_trojan_gfw_remote_read(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "remote read triggered");

	struct evbuffer *input = bufferevent_get_input(bev);

	uint64_t data_len = evbuffer_get_length(input);
	unsigned char *data = evbuffer_pullup(input, data_len);

	do_trojan_gfw_local_write(bev, ctx);
}

/*
 * inbound read handler
 * it will be enanled after upgraded
 * local -> remote
 * */
static void on_trojan_gfw_local_read(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "local read triggered");

	pgs_trojansession_ctx_t *trojan_s_ctx = session->outbound->ctx;
	if (!trojan_s_ctx->connected)
		return;

	pgs_session_debug(session, "write to remote");
	do_trojan_gfw_remote_write(bev, ctx);
}

/*
 * helper method to write data
 * from local to remote
 * local -> remote
 * */
static void do_trojan_gfw_remote_write(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	struct bufferevent *inbev = session->inbound->bev;
	struct bufferevent *outbev = session->outbound->bev;

	struct evbuffer *outboundw = bufferevent_get_output(outbev);
	struct evbuffer *inboundr = bufferevent_get_input(inbev);

	struct evbuffer *buf = outboundw;
	uint64_t len = evbuffer_get_length(inboundr);
	unsigned char *msg = evbuffer_pullup(inboundr, len);

	pgs_trojansession_ctx_t *trojan_s_ctx = session->outbound->ctx;
	uint64_t head_len = trojan_s_ctx->head_len;
	if (head_len > 0)
		len += head_len;

	if (head_len > 0) {
		evbuffer_add(buf, trojan_s_ctx->head, head_len);
		trojan_s_ctx->head_len = 0;
	}
	evbuffer_add(buf, msg, len - head_len);

	evbuffer_drain(inboundr, len - head_len);

	pgs_session_debug(session, "local -> remote: %d", len);
	on_session_metrics_send(session, len);
}

/*
 * helper method to write data
 * from remote to local
 * remote -> local
 * */
static void do_trojan_gfw_local_write(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	struct bufferevent *inbev = session->inbound->bev;
	struct bufferevent *outbev = session->outbound->bev;

	struct evbuffer *outboundr = bufferevent_get_input(outbev);
	struct evbuffer *inboundw = bufferevent_get_output(inbev);

	uint64_t data_len = evbuffer_get_length(outboundr);
	unsigned char *data = evbuffer_pullup(outboundr, data_len);

	pgs_session_debug(session, "remote -> local: %d", data_len);
	on_session_metrics_recv(session, data_len);
	evbuffer_add(inboundw, data, data_len);
	evbuffer_drain(outboundr, data_len);
}

/*
 * v2ray wss session handlers
 */
static void on_v2ray_ws_remote_event(struct bufferevent *bev, short events,
				     void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;

	if (events & BEV_EVENT_CONNECTED)
		do_v2ray_ws_remote_request(bev, ctx);
	if (events & BEV_EVENT_ERROR)
		pgs_session_error(
			session,
			"Error from bufferevent: on_v2ray_ws_remote_event");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		SSL *ssl = bufferevent_openssl_get_ssl(bev);
		if (ssl)
			pgs_ssl_close(ssl);
		bufferevent_free(bev);

		pgs_session_free(session);
	}
}
static void on_v2ray_ws_remote_read(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "remote read triggered");
	struct evbuffer *output = bufferevent_get_output(bev);
	struct evbuffer *input = bufferevent_get_input(bev);

	uint64_t data_len = evbuffer_get_length(input);
	unsigned char *data = evbuffer_pullup(input, data_len);

	pgs_vmess_ctx_t *v2ray_s_ctx = session->outbound->ctx;
	if (!v2ray_s_ctx->connected) {
		if (!strstr((const char *)data, "\r\n\r\n"))
			return;

		if (pgs_ws_upgrade_check((const char *)data)) {
			pgs_session_error(session, "websocket upgrade fail!");
			on_v2ray_ws_remote_event(bev, BEV_EVENT_ERROR, ctx);
		} else {
			//drain
			evbuffer_drain(input, data_len);
			v2ray_s_ctx->connected = true;
			// local buffer should have data already
			do_v2ray_ws_remote_write(bev, ctx);
		}
	} else {
		do_v2ray_ws_local_write(bev, ctx);
	}
}
static void on_v2ray_ws_local_read(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "local read triggered");

	pgs_vmess_ctx_t *v2ray_s_ctx = session->outbound->ctx;
	if (!v2ray_s_ctx->connected)
		return;

	pgs_session_debug(session, "write to remote");
	do_v2ray_ws_remote_write(bev, ctx);
}

static void v2ray_ws_vmess_write_cb(struct evbuffer *writer, uint8_t *data,
				    uint64_t len)
{
	pgs_ws_write_bin(writer, data, len);
}

static void do_v2ray_ws_remote_request(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	const pgs_server_config_t *config = session->outbound->config;
	const pgs_v2rayserver_config_t *vconfig = config->extra;

	pgs_session_debug(session, "do_v2ray_ws_remote_request");

	pgs_ws_req(bufferevent_get_output(session->outbound->bev),
		   vconfig->websocket.hostname, config->server_address,
		   config->server_port, vconfig->websocket.path);

	pgs_session_debug(session, "do_v2ray_ws_remote_request done");
}
static void do_v2ray_ws_remote_write(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "local -> encode -> remote");
	struct bufferevent *inbev = session->inbound->bev;
	struct bufferevent *outbev = session->outbound->bev;

	struct evbuffer *outboundw = bufferevent_get_output(outbev);
	struct evbuffer *inboundr = bufferevent_get_input(inbev);

	pgs_vmess_ctx_t *v2ray_s_ctx = session->outbound->ctx;

	uint64_t data_len = evbuffer_get_length(inboundr);
	const uint8_t *data = evbuffer_pullup(inboundr, data_len);

	uint64_t total_len = pgs_vmess_write(
		(const uint8_t *)session->outbound->config->password, data,
		data_len, v2ray_s_ctx, outboundw,
		(pgs_vmess_write_body_cb)&v2ray_ws_vmess_write_cb);

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
				// decode vmess protocol then write
				// mount to ctx
				pgs_vmess_ctx_t *v2ray_s_ctx =
					session->outbound->ctx;
				if (!pgs_vmess_parse(data + ws_meta.header_len,
						     ws_meta.payload_len,
						     v2ray_s_ctx, inboundw)) {
					pgs_session_error(
						session,
						"failed to decode vmess payload");
					on_v2ray_ws_remote_event(
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

/*
 * v2ray tcp handlers
 */
static void on_v2ray_tcp_remote_event(struct bufferevent *bev, short events,
				      void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;

	if (events & BEV_EVENT_CONNECTED) {
		pgs_vmess_ctx_t *v2ray_s_ctx = session->outbound->ctx;
		v2ray_s_ctx->connected = true;
		pgs_session_debug(session, "connected");
		on_v2ray_tcp_local_read(session->inbound->bev, ctx);
	}
	if (events & BEV_EVENT_ERROR)
		pgs_session_error(
			session,
			"Error from bufferevent: on_v2ray_tcp_remote_event");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		bufferevent_free(bev);
		pgs_session_free(session);
	}
}

static void on_v2ray_tcp_remote_read(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "remote read triggered");

	struct bufferevent *inbev = session->inbound->bev;
	struct bufferevent *outbev = session->outbound->bev;

	struct evbuffer *outboundr = bufferevent_get_input(outbev);
	struct evbuffer *inboundw = bufferevent_get_output(inbev);

	uint64_t data_len = evbuffer_get_length(outboundr);
	unsigned char *data = evbuffer_pullup(outboundr, data_len);

	pgs_vmess_ctx_t *v2ray_s_ctx = session->outbound->ctx;
	if (!pgs_vmess_parse(data, data_len, v2ray_s_ctx, inboundw)) {
		pgs_session_error(session, "failed to decode vmess payload");
		on_v2ray_tcp_remote_event(bev, BEV_EVENT_ERROR, ctx);
		return;
	}

	evbuffer_drain(outboundr, data_len);

	on_session_metrics_recv(session, data_len);
}

static void on_v2ray_tcp_local_read(struct bufferevent *bev, void *ctx)
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
		data_len, v2ray_s_ctx, outboundw,
		(pgs_vmess_write_body_cb)&evbuffer_add);

	evbuffer_drain(inboundr, data_len);
	on_session_metrics_send(session, total_len);
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
