#include "pgs_session.h"
#include "pgs_server_manager.h"
#include "pgs_log.h"
#include "unistd.h" // close
#include "pgs_util.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <assert.h>
#include <ctype.h>

#define htonll(x)                                                              \
	((1 == htonl(1)) ?                                                     \
		 (x) :                                                         \
		 ((uint64_t)htonl((x)&0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) htonll(x)

const char *ws_key = "dGhlIHNhbXBsZSBub25jZQ==";
const char *ws_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

/*
 * local handlers
 */
static void on_local_event(pgs_bev_t *bev, short events, void *ctx);
static void on_local_read(pgs_bev_t *bev, void *ctx);

/*
 * trojan websocket session handler
 */
static void on_trojan_ws_remote_event(pgs_bev_t *bev, short events, void *ctx);
static void on_trojan_ws_remote_read(pgs_bev_t *bev, void *ctx);
static void on_trojan_ws_local_read(pgs_bev_t *bev, void *ctx);
static void do_trojan_ws_remote_request(pgs_bev_t *bev, void *ctx);
static void do_trojan_ws_remote_write(pgs_bev_t *bev, void *ctx);
static void do_trojan_ws_local_write(pgs_bev_t *bev, void *ctx);

/*
 * trojan gfw session handler
 */
static void on_trojan_gfw_remote_event(pgs_bev_t *bev, short events, void *ctx);
static void on_trojan_gfw_remote_read(pgs_bev_t *bev, void *ctx);
static void on_trojan_gfw_local_read(pgs_bev_t *bev, void *ctx);
static void do_trojan_gfw_remote_write(pgs_bev_t *bev, void *ctx);
static void do_trojan_gfw_local_write(pgs_bev_t *bev, void *ctx);

/*
 * metrics
 */
static void on_session_metrics_recv(pgs_session_t *session, pgs_size_t len);
static void on_session_metrics_send(pgs_session_t *session, pgs_size_t len);

/**
 * Create New Sesson
 *
 * @param fd the local socket fd
 * @param local_address the local_server object
 *  which contains logger, base, etc..
 * @return a pointer of new session
 */
pgs_session_t *pgs_session_new(pgs_socket_t fd,
			       pgs_local_server_t *local_server)
{
	pgs_session_t *ptr = pgs_malloc(sizeof(pgs_session_t));

	pgs_conn_t *local_conn = pgs_conn_new(fd);
	pgs_bev_t *bev = pgs_bev_socket_new(local_server->base, fd,
					    BEV_OPT_CLOSE_ON_FREE);
	ptr->inbound = pgs_session_inbound_new(local_conn, bev);

	ptr->outbound = NULL;

	// init metrics
	ptr->metrics = pgs_malloc(sizeof(pgs_server_session_stats_t));
	ptr->metrics->start = time(NULL);
	ptr->metrics->end = time(NULL);
	ptr->metrics->recv = 0;
	ptr->metrics->send = 0;

	ptr->local_server = local_server;

	// init socks5 structure
	ptr->fsm_socks5.state = AUTH;
	ptr->fsm_socks5.rbuf = ptr->inbound->conn->rbuf;
	ptr->fsm_socks5.wbuf = ptr->inbound->conn->wbuf;
	ptr->fsm_socks5.read_bytes_ptr = &ptr->inbound->conn->read_bytes;
	ptr->fsm_socks5.write_bytes_ptr = &ptr->inbound->conn->write_bytes;

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
	pgs_bev_t *bev = session->inbound->bev;

	pgs_bev_setcb(bev, on_local_read, NULL, on_local_event, session);
	pgs_bev_enable(bev, EV_READ);
}

void pgs_session_free(pgs_session_t *session)
{
	if (session->inbound)
		pgs_session_inbound_free(session->inbound);

	if (session->outbound) {
		session->metrics->end = time(NULL);
		const char *addr = session->outbound->dest;
		LTRIM(addr);
		// TODO: emit metrics
		// session->local_server->sm
		pgs_session_info(
			session,
			"connection to %s:%d closed, send: %d, recv: %d", addr,
			session->outbound->port, session->metrics->send,
			session->metrics->recv);
		pgs_session_outbound_free(session->outbound);
	}

	if (session->metrics)
		pgs_free(session->metrics);

	pgs_free(session);
}

pgs_session_inbound_t *pgs_session_inbound_new(pgs_conn_t *conn, pgs_bev_t *bev)
{
	pgs_session_inbound_t *ptr = pgs_malloc(sizeof(pgs_session_inbound_t));
	ptr->conn = conn;
	ptr->bev = bev;
	return ptr;
}

void pgs_session_inbound_free(pgs_session_inbound_t *sb)
{
	if (sb->conn) {
		pgs_conn_free(sb->conn);
	}
	if (sb->bev) {
		pgs_bev_free(sb->bev);
	}
	pgs_free(sb);
}

pgs_trojansession_ctx_t *pgs_trojansession_ctx_new(const char *encodepass,
						   pgs_size_t passlen,
						   const char *cmd,
						   pgs_size_t cmdlen)
{
	if (passlen != SHA224_LEN * 2 || cmdlen < 3)
		return NULL;
	pgs_trojansession_ctx_t *ptr =
		pgs_malloc(sizeof(pgs_trojansession_ctx_t));
	ptr->head_len = passlen + 2 + 1 + cmdlen - 3 + 2;
	ptr->head = pgs_malloc(sizeof(char) * ptr->head_len);

	// sha224(password) + "\r\n" + cmd[1] + cmd.substr(3) + "\r\n"
	pgs_memcpy(ptr->head, encodepass, passlen);
	ptr->head[passlen] = '\r';
	ptr->head[passlen + 1] = '\n';
	ptr->head[passlen + 2] = cmd[1];
	pgs_memcpy(ptr->head + passlen + 3, cmd + 3, cmdlen - 3);
	ptr->head[ptr->head_len - 2] = '\r';
	ptr->head[ptr->head_len - 1] = '\n';

	ptr->connected = false;
	return ptr;
}

void pgs_trojansession_ctx_free(pgs_trojansession_ctx_t *ctx)
{
	if (ctx->head)
		pgs_free(ctx->head);
	ctx->head = NULL;
	pgs_free(ctx);
	ctx = NULL;
}

pgs_session_outbound_t *
pgs_session_outbound_new(pgs_session_t *session,
			 const pgs_server_config_t *config)
{
	pgs_session_outbound_t *ptr =
		pgs_malloc(sizeof(pgs_session_outbound_t));
	ptr->config = config;
	ptr->config_idx = -1;
	for (int i = 0; i < session->local_server->config->servers_count; i++) {
		if (config == &session->local_server->config->servers[i]) {
			ptr->config_idx = i;
			break;
		}
	}
	ptr->bev = NULL;
	ptr->ctx = NULL;

	const char *cmd = (const char *)session->inbound->conn->rbuf;
	pgs_size_t cmd_len = session->inbound->conn->read_bytes;

	int len = cmd_len - 2 - 4;
	ptr->dest = pgs_malloc(sizeof(char) * (len + 1));
	ptr->dest[len] = '\0';
	pgs_memcpy(ptr->dest, cmd + 4, len);
	ptr->port = cmd[cmd_len - 2] << 8 | cmd[cmd_len - 1];

	if (strcmp(config->server_type, "trojan") == 0) {
		pgs_trojanserver_config_t *trojanconf = config->extra;
		ptr->ctx = pgs_trojansession_ctx_new(config->password, 56, cmd,
						     cmd_len);

		pgs_ssl_t *ssl = pgs_ssl_new(trojanconf->ssl_ctx,
					     (void *)config->server_address);
		if (ssl == NULL) {
			fprintf(stderr, "SSL_new");
			goto error;
		}
		ptr->bev = pgs_bev_openssl_socket_new(
			session->local_server->base, -1, ssl,
			BUFFEREVENT_SSL_CONNECTING,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
		pgs_bev_openssl_set_allow_dirty_shutdown(ptr->bev, 1);

		if (trojanconf->websocket.enabled) {
			// websocket support(trojan-go)
			pgs_bev_setcb(ptr->bev, on_trojan_ws_remote_read, NULL,
				      on_trojan_ws_remote_event, session);
			pgs_bev_setcb(session->inbound->bev,
				      on_trojan_ws_local_read, NULL,
				      on_local_event, session);
			pgs_bev_enable(ptr->bev, EV_READ);
		} else {
			// trojan-gfw
			pgs_bev_setcb(ptr->bev, on_trojan_gfw_remote_read, NULL,
				      on_trojan_gfw_remote_event, session);
			pgs_bev_setcb(session->inbound->bev,
				      on_trojan_gfw_local_read, NULL,
				      on_local_event, session);
			pgs_bev_enable(ptr->bev, EV_READ);
		}
	}

	return ptr;
error:
	pgs_session_outbound_free(ptr);
	return NULL;
}

void pgs_session_outbound_free(pgs_session_outbound_t *ptr)
{
	if (ptr->bev)
		pgs_bev_free(ptr->bev);
	if (ptr->ctx) {
		if (strcmp(ptr->config->server_type, "trojan") == 0) {
			pgs_trojansession_ctx_free(ptr->ctx);
		}
	}
	if (ptr->dest)
		pgs_free(ptr->dest);
	ptr->bev = NULL;
	ptr->ctx = NULL;
	ptr->dest = NULL;
	pgs_free(ptr);
	ptr = NULL;
}

void pgs_session_outbound_run(pgs_session_t *session)
{
	const pgs_server_config_t *config = session->outbound->config;
	pgs_session_debug(session, "connect: %s:%d", config->server_address,
			  config->server_port);
	pgs_bev_socket_connect_hostname(session->outbound->bev,
					session->local_server->dns_base,
					AF_INET, config->server_address,
					config->server_port);
}

/**
 * inbound event handler
 */
static void on_local_event(pgs_bev_t *bev, short events, void *ctx)
{
	// free buffer event and related session
	pgs_session_t *session = (pgs_session_t *)ctx;
	if (events & BEV_EVENT_ERROR)
		pgs_session_error(session, "Error from bufferevent");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		pgs_bev_free(bev);
		pgs_session_free(session);
	}
}

/*
 * inbound on read handler
 * socks5 handshake -> proxy
 */
static void on_local_read(pgs_bev_t *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "read triggered");
	// Socks5 local
	// Then choose server type
	pgs_evbuffer_t *output = pgs_bev_get_output(bev);
	pgs_evbuffer_t *input = pgs_bev_get_input(bev);

	pgs_conn_t *conn = session->inbound->conn;

	// read from local
	conn->read_bytes =
		pgs_evbuffer_remove(input, conn->rbuf, sizeof conn->rbuf);
	pgs_session_debug_buffer(session, (unsigned char *)conn->rbuf,
				 conn->read_bytes);

	if (session->fsm_socks5.state != PROXY) {
		// socks5 fsm
		pgs_socks5_step(&session->fsm_socks5);
		if (session->fsm_socks5.state == ERR) {
			pgs_session_error(session, "%s",
					  session->fsm_socks5.err_msg);
			on_local_event(bev, BEV_EVENT_ERROR, ctx);
		}
		pgs_session_debug(session, "response: ");
		pgs_session_debug_buffer(session, (unsigned char *)conn->wbuf,
					 conn->write_bytes);
		// repsond to local socket
		pgs_evbuffer_add(output, conn->wbuf, conn->write_bytes);
		if (session->fsm_socks5.state == PROXY) {
			pgs_server_config_t *config =
				pgs_server_manager_get_config(
					session->local_server->sm);
			// TODO: log destination and do metrics
			// 1. local -> remote total/seconds
			// 2. remote -> local total/seconds
			// 3. avg connect time
			session->outbound =
				pgs_session_outbound_new(session, config);

			const char *addr = session->outbound->dest;
			LTRIM(addr);
			pgs_session_info(session, "--> %s:%d", addr,
					 session->outbound->port);

			pgs_session_outbound_run(session);
		}
		return;
	} else {
		pgs_session_error(session, "unreachable");
		pgs_bev_free(bev);
		pgs_session_free(session);
	}
}

/**
 * outound event handler
 */
static void on_trojan_ws_remote_event(pgs_bev_t *bev, short events, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;

	if (events & BEV_EVENT_CONNECTED)
		do_trojan_ws_remote_request(bev, ctx);
	if (events & BEV_EVENT_ERROR)
		pgs_session_error(session, "Error from bufferevent");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		pgs_ssl_t *ssl = pgs_bev_openssl_get_ssl(bev);
		if (ssl)
			pgs_ssl_close(ssl);
		pgs_bev_free(bev);

		pgs_session_free(session);
	}
}

/*
 * outound read handler
 * it will handle websocket upgrade or 
 * remote -> decode(ws frame) -> local
 */
static void on_trojan_ws_remote_read(pgs_bev_t *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "remote read triggered");
	pgs_evbuffer_t *output = pgs_bev_get_output(bev);
	pgs_evbuffer_t *input = pgs_bev_get_input(bev);

	pgs_size_t data_len = pgs_evbuffer_get_length(input);
	unsigned char *data = pgs_evbuffer_pullup(input, data_len);
	// read from remote
	pgs_session_debug_buffer(session, data, data_len);

	pgs_trojansession_ctx_t *trojan_s_ctx = session->outbound->ctx;
	if (!trojan_s_ctx->connected) {
		if (!strstr((const char *)data, "\r\n\r\n"))
			return;

		if (strncmp((const char *)data, "HTTP/1.1 101",
			    strlen("HTTP/1.1 101")) != 0 ||
		    !strstr((const char *)data, ws_accept)) {
			pgs_session_error(session, "websocket upgrade fail!");
			on_trojan_ws_remote_event(bev, BEV_EVENT_ERROR, ctx);
		} else {
			//drain
			pgs_evbuffer_drain(input, data_len);
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
static void on_trojan_ws_local_read(pgs_bev_t *bev, void *ctx)
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
static void do_trojan_ws_remote_request(pgs_bev_t *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	const pgs_server_config_t *config = session->outbound->config;
	const pgs_trojanserver_config_t *trojanconfig = config->extra;

	pgs_evbuffer_t *out = pgs_bev_get_output(session->outbound->bev);

	pgs_session_debug(session, "do_trojan_ws_remote_request");

	pgs_evbuffer_add_printf(out, "GET %s HTTP/1.1\r\n",
				trojanconfig->websocket.path);
	pgs_evbuffer_add_printf(out, "Host:%s:%d\r\n",
				trojanconfig->websocket.hostname,
				config->server_port);
	pgs_evbuffer_add_printf(out, "Upgrade:websocket\r\n");
	pgs_evbuffer_add_printf(out, "Connection:upgrade\r\n");
	pgs_evbuffer_add_printf(out, "Sec-WebSocket-Key:%s\r\n", ws_key);
	pgs_evbuffer_add_printf(out, "Sec-WebSocket-Version:13\r\n");
	pgs_evbuffer_add_printf(
		out, "Origin:https://%s:%d\r\n", config->server_address,
		config->server_port); //missing this key will lead to 403 response.
	pgs_evbuffer_add_printf(out, "\r\n");
	pgs_session_debug(session, "do_trojan_ws_remote_request done");
}

/*
 * helper method to write data
 * from local to remote
 * local -> encode(ws frame) -> remote
 * */
static void do_trojan_ws_remote_write(pgs_bev_t *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "local -> encode -> remote");
	pgs_bev_t *inbev = session->inbound->bev;
	pgs_bev_t *outbev = session->outbound->bev;

	pgs_evbuffer_t *outboundw = pgs_bev_get_output(outbev);
	pgs_evbuffer_t *inboundr = pgs_bev_get_input(inbev);

	pgs_evbuffer_t *buf = outboundw;
	pgs_size_t len = pgs_evbuffer_get_length(inboundr);
	unsigned char *msg = pgs_evbuffer_pullup(inboundr, len);
	pgs_session_debug_buffer(session, msg, len);

	pgs_trojansession_ctx_t *trojan_s_ctx = session->outbound->ctx;
	pgs_size_t head_len = trojan_s_ctx->head_len;
	if (head_len > 0)
		len += head_len;

	uint8_t a = 0;
	a |= 1 << 7; //fin
	a |= 1; //text frame

	uint8_t b = 0;
	b |= 1 << 7; //mask

	uint16_t c = 0;
	uint64_t d = 0;

	//payload len
	if (len < 126) {
		b |= len;
	} else if (len < (1 << 16)) {
		b |= 126;
		c = htons(len);
	} else {
		b |= 127;
		d = htonll(len);
	}

	pgs_evbuffer_add(buf, &a, 1);
	pgs_evbuffer_add(buf, &b, 1);

	if (c)
		pgs_evbuffer_add(buf, &c, sizeof(c));
	else if (d)
		pgs_evbuffer_add(buf, &d, sizeof(d));

	// tls will protect data
	// mask data makes nonsense
	uint8_t mask_key[4] = { 0, 0, 0, 0 };
	pgs_evbuffer_add(buf, &mask_key, 4);

	if (head_len > 0) {
		pgs_evbuffer_add(buf, trojan_s_ctx->head, head_len);
		trojan_s_ctx->head_len = 0;
		pgs_session_debug_buffer(
			session, (unsigned char *)trojan_s_ctx->head, head_len);
	}
	// x ^ 0 = x
	pgs_evbuffer_add(buf, msg, len - head_len);

	pgs_evbuffer_drain(inboundr, len - head_len);

	on_session_metrics_send(session, len);
}

/*
 * helper method to write data
 * from remote to local
 * remote -> decode(ws frame) -> local
 * */
static void do_trojan_ws_local_write(pgs_bev_t *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "remote -> decode -> local");
	pgs_bev_t *inbev = session->inbound->bev;
	pgs_bev_t *outbev = session->outbound->bev;

	pgs_evbuffer_t *outboundr = pgs_bev_get_input(outbev);
	pgs_evbuffer_t *inboundw = pgs_bev_get_output(inbev);

	pgs_size_t data_len = pgs_evbuffer_get_length(outboundr);
	if (data_len < 2)
		return;

	unsigned char *data = pgs_evbuffer_pullup(outboundr, data_len);

	int fin = !!(*data & 0x80);
	int opcode = *data & 0x0F;
	int mask = !!(*(data + 1) & 0x80);
	uint64_t payload_len = *(data + 1) & 0x7F;

	size_t header_len = 2 + (mask ? 4 : 0);

	if (payload_len < 126) {
		if (header_len > data_len)
			return;

	} else if (payload_len == 126) {
		header_len += 2;
		if (header_len > data_len)
			return;

		payload_len = ntohs(*(uint16_t *)(data + 2));

	} else if (payload_len == 127) {
		header_len += 8;
		if (header_len > data_len)
			return;

		payload_len = ntohll(*(uint64_t *)(data + 2));
	}

	if (header_len + payload_len > data_len)
		return;

	const unsigned char *mask_key = data + header_len - 4;

	for (int i = 0; mask && i < payload_len; i++)
		data[header_len + i] ^= mask_key[i % 4];

	if (opcode == 0x01) {
		// write to local
		pgs_evbuffer_add(inboundw, data + header_len, payload_len);
	}

	if (!fin)
		pgs_session_debug(session, "frame to be continue..");

	pgs_evbuffer_drain(outboundr, header_len + payload_len);

	on_session_metrics_recv(session, header_len + payload_len);

	//next frame
	do_trojan_ws_local_write(bev, ctx);
}

/*
 * trojan gfw event handler
 */
static void on_trojan_gfw_remote_event(pgs_bev_t *bev, short events, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;

	if (events & BEV_EVENT_CONNECTED) {
		pgs_session_debug(session, "connected");
		pgs_trojansession_ctx_t *trojan_s_ctx = session->outbound->ctx;
		trojan_s_ctx->connected = true;
		do_trojan_gfw_remote_write(bev, ctx);
	}
	if (events & BEV_EVENT_ERROR)
		pgs_session_error(session, "Error from bufferevent");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		pgs_ssl_t *ssl = pgs_bev_openssl_get_ssl(bev);
		if (ssl)
			pgs_ssl_close(ssl);
		pgs_bev_free(bev);
		pgs_session_error(session, "EOF from remote, free session");
		pgs_session_free(session);
	}
}

/*
 * outound read handler
 * it will handle websocket upgrade or 
 * remote -> local
 */
static void on_trojan_gfw_remote_read(pgs_bev_t *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "remote read triggered");

	pgs_evbuffer_t *input = pgs_bev_get_input(bev);

	pgs_size_t data_len = pgs_evbuffer_get_length(input);
	unsigned char *data = pgs_evbuffer_pullup(input, data_len);
	// read from remote
	pgs_session_debug_buffer(session, data, data_len);

	do_trojan_gfw_local_write(bev, ctx);
}

/*
 * inbound read handler
 * it will be enanled after upgraded
 * local -> remote
 * */
static void on_trojan_gfw_local_read(pgs_bev_t *bev, void *ctx)
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
static void do_trojan_gfw_remote_write(pgs_bev_t *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_bev_t *inbev = session->inbound->bev;
	pgs_bev_t *outbev = session->outbound->bev;

	pgs_evbuffer_t *outboundw = pgs_bev_get_output(outbev);
	pgs_evbuffer_t *inboundr = pgs_bev_get_input(inbev);

	pgs_evbuffer_t *buf = outboundw;
	pgs_size_t len = pgs_evbuffer_get_length(inboundr);
	unsigned char *msg = pgs_evbuffer_pullup(inboundr, len);
	pgs_session_debug_buffer(session, msg, len);

	pgs_trojansession_ctx_t *trojan_s_ctx = session->outbound->ctx;
	pgs_size_t head_len = trojan_s_ctx->head_len;
	if (head_len > 0)
		len += head_len;

	if (head_len > 0) {
		pgs_evbuffer_add(buf, trojan_s_ctx->head, head_len);
		trojan_s_ctx->head_len = 0;
		pgs_session_debug_buffer(
			session, (unsigned char *)trojan_s_ctx->head, head_len);
	}
	pgs_evbuffer_add(buf, msg, len - head_len);

	pgs_evbuffer_drain(inboundr, len - head_len);

	pgs_session_debug(session, "local -> remote: %d", len);
	on_session_metrics_send(session, len);
}

/*
 * helper method to write data
 * from remote to local
 * remote -> local
 * */
static void do_trojan_gfw_local_write(pgs_bev_t *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_bev_t *inbev = session->inbound->bev;
	pgs_bev_t *outbev = session->outbound->bev;

	pgs_evbuffer_t *outboundr = pgs_bev_get_input(outbev);
	pgs_evbuffer_t *inboundw = pgs_bev_get_output(inbev);

	pgs_size_t data_len = pgs_evbuffer_get_length(outboundr);
	unsigned char *data = pgs_evbuffer_pullup(outboundr, data_len);

	pgs_session_debug(session, "remote -> local: %d", data_len);
	on_session_metrics_recv(session, data_len);
	pgs_evbuffer_add(inboundw, data, data_len);
	pgs_evbuffer_drain(outboundr, data_len);
}

static void on_session_metrics_recv(pgs_session_t *session, pgs_size_t len)
{
	if (!session->metrics)
		return;
	session->metrics->recv += len;
}

static void on_session_metrics_send(pgs_session_t *session, pgs_size_t len)
{
	if (!session->metrics)
		return;
	session->metrics->send += len;
}
