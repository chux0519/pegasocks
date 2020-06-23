#include "crm_session.h"
#include "crm_log.h"
#include "unistd.h" // close
#include "crm_util.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <assert.h>

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
static void on_local_event(crm_bev_t *bev, short events, void *ctx);
static void on_local_read(crm_bev_t *bev, void *ctx);

/*
 * trojan websocket session handler
 */
static void on_trojan_ws_remote_event(crm_bev_t *bev, short events, void *ctx);
static void on_trojan_ws_remote_read(crm_bev_t *bev, void *ctx);
static void on_trojan_ws_local_read(crm_bev_t *bev, void *ctx);
static void do_trojan_ws_remote_request(crm_bev_t *bev, void *ctx);
static void do_trojan_ws_remote_write(crm_bev_t *bev, void *ctx);
static void do_trojan_ws_local_write(crm_bev_t *bev, void *ctx);

/**
 * Create New Sesson
 *
 * @param fd the local socket fd
 * @param local_address the local_server object
 *  which contains logger, base, etc..
 * @return a pointer of new session
 */
crm_session_t *crm_session_new(crm_socket_t fd,
			       crm_local_server_t *local_server)
{
	crm_session_t *ptr = crm_malloc(sizeof(crm_session_t));

	crm_conn_t *local_conn = crm_conn_new(fd);
	crm_bev_t *bev = crm_bev_socket_new(local_server->base, fd,
					    BEV_OPT_CLOSE_ON_FREE);
	ptr->inbound = crm_session_inbound_new(local_conn, bev);

	ptr->outbound = NULL;

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
void crm_session_start(crm_session_t *session)
{
	// new connection, setup a bufferevent for it
	crm_bev_t *bev = session->inbound->bev;

	crm_bev_setcb(bev, on_local_read, NULL, on_local_event, session);
	crm_bev_enable(bev, EV_READ);
}

void crm_session_free(crm_session_t *session)
{
	if (session->inbound) {
		crm_session_inbound_free(session->inbound);
	}
	if (session->outbound) {
		crm_session_outbound_free(session->outbound);
	}
	crm_free(session);
}

crm_session_inbound_t *crm_session_inbound_new(crm_conn_t *conn, crm_bev_t *bev)
{
	crm_session_inbound_t *ptr = crm_malloc(sizeof(crm_session_inbound_t));
	ptr->conn = conn;
	ptr->bev = bev;
	return ptr;
}

void crm_session_inbound_free(crm_session_inbound_t *sb)
{
	if (sb->conn) {
		crm_conn_free(sb->conn);
	}
	if (sb->bev) {
		crm_bev_free(sb->bev);
	}
	crm_free(sb);
}

crm_trojansession_ctx_t *crm_trojansession_ctx_new(const char *encodepass,
						   crm_size_t passlen,
						   const char *cmd,
						   crm_size_t cmdlen)
{
	if (passlen != SHA224_LEN * 2 || cmdlen < 3)
		return NULL;
	crm_trojansession_ctx_t *ptr =
		crm_malloc(sizeof(crm_trojansession_ctx_t));
	ptr->head_len = passlen + 2 + 1 + cmdlen - 3 + 2;
	ptr->head = crm_malloc(sizeof(char) * ptr->head_len);

	// sha224(password) + "\r\n" + cmd[1] + cmd.substr(3) + "\r\n"
	crm_memcpy(ptr->head, encodepass, passlen);
	ptr->head[passlen] = '\r';
	ptr->head[passlen + 1] = '\n';
	ptr->head[passlen + 2] = cmd[1];
	crm_memcpy(ptr->head + passlen + 3, cmd + 3, cmdlen - 3);
	ptr->head[ptr->head_len - 2] = '\r';
	ptr->head[ptr->head_len - 1] = '\n';

	ptr->upgraded = false;
	return ptr;
}

void crm_trojansession_ctx_free(crm_trojansession_ctx_t *ctx)
{
	if (ctx->head)
		crm_free(ctx->head);
	ctx->head = NULL;
	crm_free(ctx);
	ctx = NULL;
}

crm_session_outbound_t *
crm_session_outbound_new(crm_session_t *session,
			 const crm_server_config_t *config)
{
	crm_session_outbound_t *ptr =
		crm_malloc(sizeof(crm_session_outbound_t));
	ptr->config = config;
	ptr->bev = NULL;
	ptr->ctx = NULL;

	if (strcmp(config->server_type, "trojan") == 0) {
		crm_trojanserver_config_t *trojanconf = config->extra;
		ptr->ctx = crm_trojansession_ctx_new(
			config->password, 56,
			(const char *)session->inbound->conn->rbuf,
			session->inbound->conn->read_bytes);

		SSL *ssl = SSL_new(trojanconf->ssl_ctx);
		if (ssl == NULL) {
			fprintf(stderr, "SSL_new");
			goto error;
		}
		SSL_set_tlsext_host_name(ssl, config->server_address);
		ptr->bev = bufferevent_openssl_socket_new(
			session->local_server->base, -1, ssl,
			BUFFEREVENT_SSL_CONNECTING,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
		bufferevent_openssl_set_allow_dirty_shutdown(ptr->bev, 1);

		if (trojanconf->websocket.enabled) {
			// websocket support(trojan-go)
			crm_bev_setcb(ptr->bev, on_trojan_ws_remote_read, NULL,
				      on_trojan_ws_remote_event, session);
			crm_bev_setcb(session->inbound->bev,
				      on_trojan_ws_local_read, NULL,
				      on_local_event, session);
			bufferevent_enable(ptr->bev, EV_READ);
		} else {
			// trojan-gfw
			// TODO:
		}
	}

	return ptr;
error:
	crm_session_outbound_free(ptr);
	return NULL;
}

void crm_session_outbound_free(crm_session_outbound_t *ptr)
{
	if (ptr->bev)
		crm_bev_free(ptr->bev);
	if (ptr->ctx) {
		if (strcmp(ptr->config->server_type, "trojan") == 0) {
			crm_trojansession_ctx_free(ptr->ctx);
		}
	}
	ptr->bev = NULL;
	ptr->ctx = NULL;
	crm_free(ptr);
	ptr = NULL;
}

void crm_session_outbound_run(crm_session_t *session)
{
	const crm_server_config_t *config = session->outbound->config;
	crm_session_debug(session, "connect: %s:%d", config->server_address,
			  config->server_port);
	bufferevent_socket_connect_hostname(session->outbound->bev,
					    session->local_server->dns_base,
					    AF_INET, config->server_address,
					    config->server_port);
}

/**
 * inbound event handler
 */
static void on_local_event(crm_bev_t *bev, short events, void *ctx)
{
	// free buffer event and related session
	crm_session_t *session = (crm_session_t *)ctx;
	if (events & BEV_EVENT_ERROR)
		crm_session_error(session, "Error from bufferevent");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		crm_bev_free(bev);
		crm_session_error(session, "EOF from local, free session");
		crm_session_free(session);
	}
}

/*
 * inbound on read handler
 * socks5 handshake -> proxy
 */
static void on_local_read(crm_bev_t *bev, void *ctx)
{
	crm_session_t *session = (crm_session_t *)ctx;
	crm_session_debug(session, "read triggered");
	// Socks5 local
	// Then choose server type
	struct evbuffer *output = crm_bev_get_output(bev);
	struct evbuffer *input = crm_bev_get_input(bev);

	crm_conn_t *conn = session->inbound->conn;

	// read from local
	conn->read_bytes =
		evbuffer_remove(input, conn->rbuf, sizeof conn->rbuf);
	crm_session_debug_buffer(session, (unsigned char *)conn->rbuf,
				 conn->read_bytes);

	if (session->fsm_socks5.state != PROXY) {
		// socks5 fsm
		crm_socks5_step(&session->fsm_socks5);
		if (session->fsm_socks5.state == ERR) {
			crm_session_error(session, "%s",
					  session->fsm_socks5.err_msg);
			on_local_event(bev, BEV_EVENT_ERROR, ctx);
		}
		crm_session_debug(session, "response: ");
		crm_session_debug_buffer(session, (unsigned char *)conn->wbuf,
					 conn->write_bytes);
		// repsond to local socket
		evbuffer_add(output, conn->wbuf, conn->write_bytes);
		if (session->fsm_socks5.state == PROXY) {
			crm_server_config_t *config =
				&session->local_server->config->servers[0];
			session->outbound =
				crm_session_outbound_new(session, config);
			crm_session_outbound_run(session);
		}
		return;
	} else {
		// unreachable
		crm_session_error(session, "unreachable");
	}
}

/**
 * outound event handler
 */
static void on_trojan_ws_remote_event(crm_bev_t *bev, short events, void *ctx)
{
	crm_session_t *session = (crm_session_t *)ctx;
	int e = bufferevent_socket_get_dns_error(bev);
	crm_session_debug(session, "events: %x, dns err: %d, %s", events, e,
			  evutil_gai_strerror(e));
	ERR_print_errors_fp(stderr);

	if (events & BEV_EVENT_CONNECTED)
		do_trojan_ws_remote_request(bev, ctx);
	if (events & BEV_EVENT_ERROR)
		crm_session_error(session, "Error from bufferevent");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		crm_bev_free(bev);
		crm_session_error(session, "EOF from remote, free session");
		crm_session_free(session);
	}
}

/*
 * outound read handler
 * it will handle websocket upgrade or 
 * remote -> decode(ws frame) -> local
 */
static void on_trojan_ws_remote_read(crm_bev_t *bev, void *ctx)
{
	crm_session_t *session = (crm_session_t *)ctx;
	crm_session_debug(session, "remote read triggered");
	struct evbuffer *output = crm_bev_get_output(bev);
	struct evbuffer *input = crm_bev_get_input(bev);

	crm_size_t data_len = evbuffer_get_length(input);
	unsigned char *data = evbuffer_pullup(input, data_len);
	// read from remote
	crm_session_debug_buffer(session, data, data_len);

	crm_trojansession_ctx_t *trojan_s_ctx = session->outbound->ctx;
	if (!trojan_s_ctx->upgraded) {
		if (!strstr((const char *)data, "\r\n\r\n"))
			return;

		if (strncmp((const char *)data, "HTTP/1.1 101",
			    strlen("HTTP/1.1 101")) != 0 ||
		    !strstr((const char *)data, ws_accept)) {
			crm_session_error(session, "websocket upgrade fail!");
			on_trojan_ws_remote_event(bev, BEV_EVENT_ERROR, ctx);
		} else {
			//drain
			evbuffer_drain(input, data_len);
			trojan_s_ctx->upgraded = true;
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
static void on_trojan_ws_local_read(crm_bev_t *bev, void *ctx)
{
	crm_session_t *session = (crm_session_t *)ctx;
	crm_session_debug(session, "local read triggered");

	crm_trojansession_ctx_t *trojan_s_ctx = session->outbound->ctx;
	if (!trojan_s_ctx->upgraded)
		return;

	crm_session_debug(session, "write to remote");
	do_trojan_ws_remote_write(bev, ctx);
}

/*
 * outbound websocket handshake
 * */
static void do_trojan_ws_remote_request(crm_bev_t *bev, void *ctx)
{
	crm_session_t *session = (crm_session_t *)ctx;
	const crm_server_config_t *config = session->outbound->config;
	const crm_trojanserver_config_t *trojanconfig = config->extra;

	struct evbuffer *out = bufferevent_get_output(session->outbound->bev);

	crm_session_debug(session, "do_trojan_ws_remote_request");

	evbuffer_add_printf(out, "GET %s HTTP/1.1\r\n",
			    trojanconfig->websocket.path);
	evbuffer_add_printf(out, "Host:%s:%d\r\n", config->server_address,
			    config->server_port);
	evbuffer_add_printf(out, "Upgrade:websocket\r\n");
	evbuffer_add_printf(out, "Connection:upgrade\r\n");
	evbuffer_add_printf(out, "Sec-WebSocket-Key:%s\r\n", ws_key);
	evbuffer_add_printf(out, "Sec-WebSocket-Version:13\r\n");
	evbuffer_add_printf(
		out, "Origin:https://%s:%d\r\n", config->server_address,
		config->server_port); //missing this key will lead to 403 response.
	evbuffer_add_printf(out, "\r\n");
	crm_session_debug(session, "do_trojan_ws_remote_request done");
}

/*
 * helper method to write data
 * from local to remote
 * local -> encode(ws frame) -> remote
 * */
static void do_trojan_ws_remote_write(crm_bev_t *bev, void *ctx)
{
	crm_session_t *session = (crm_session_t *)ctx;
	crm_session_debug(session, "local -> encode -> remote");
	crm_bev_t *inbev = session->inbound->bev;
	crm_bev_t *outbev = session->outbound->bev;

	struct evbuffer *outboundw = crm_bev_get_output(outbev);
	struct evbuffer *inboundr = crm_bev_get_input(inbev);

	struct evbuffer *buf = outboundw;
	crm_size_t len = evbuffer_get_length(inboundr);
	unsigned char *msg = evbuffer_pullup(inboundr, len);
	crm_session_debug_buffer(session, msg, len);

	crm_trojansession_ctx_t *trojan_s_ctx = session->outbound->ctx;
	crm_size_t head_len = trojan_s_ctx->head_len;
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

	evbuffer_add(buf, &a, 1);
	evbuffer_add(buf, &b, 1);

	if (c)
		evbuffer_add(buf, &c, sizeof(c));
	else if (d)
		evbuffer_add(buf, &d, sizeof(d));

	// tls will protect data
	// mask data makes nonsense
	uint8_t mask_key[4] = { 0, 0, 0, 0 };
	evbuffer_add(buf, &mask_key, 4);

	if (head_len > 0) {
		evbuffer_add(buf, trojan_s_ctx->head, head_len);
		trojan_s_ctx->head_len = 0;
		crm_session_debug_buffer(
			session, (unsigned char *)trojan_s_ctx->head, head_len);
	}
	// x ^ 0 = x
	evbuffer_add(buf, msg, len - head_len);

	evbuffer_drain(inboundr, len - head_len);
}

/*
 * helper method to write data
 * from remote to local
 * remote -> decode(ws frame) -> local
 * */
static void do_trojan_ws_local_write(crm_bev_t *bev, void *ctx)
{
	crm_session_t *session = (crm_session_t *)ctx;
	crm_session_debug(session, "remote -> decode -> local");
	crm_bev_t *inbev = session->inbound->bev;
	crm_bev_t *outbev = session->outbound->bev;

	struct evbuffer *outboundr = crm_bev_get_input(outbev);
	struct evbuffer *inboundw = crm_bev_get_output(inbev);

	crm_size_t data_len = evbuffer_get_length(outboundr);
	if (data_len < 2)
		return;

	unsigned char *data = evbuffer_pullup(outboundr, data_len);

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
		evbuffer_add(inboundw, data + header_len, payload_len);
	}

	if (!fin)
		crm_session_debug(session, "frame to be continue..");

	evbuffer_drain(outboundr, header_len + payload_len);

	//next frame
	do_trojan_ws_local_write(bev, ctx);
}
