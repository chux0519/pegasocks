#include "session/session.h"
#include "session/filter.h"

#ifndef USE_MBEDTLS
#include <openssl/ssl.h>
#endif

#include <netinet/tcp.h>

const unsigned char g204_cmd[] = { 0x05, 0x01, 0x00, 0x03, 0x0d, 0x77, 0x77,
				   0x77, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
				   0x65, 0x2e, 0x63, 0x6e, 0x00, 0x50 };

const char g204_http_req[] =
	"GET /generate_204 HTTP/1.1\r\nHost: www.google.cn\r\n\r\n";

#ifdef WITH_ACL
static void dns_cb(int result, char type, int count, int ttl, void *addrs,
		   void *arg)
{
	pgs_session_t *session = arg;
	int i;
	char dest[32] = { 0 };
	size_t raw_cmd_len = 4 + 4 + 2;
	uint8_t raw_cmd[10] = { 0 };

	for (i = 0; i < count; ++i) {
		if (type == DNS_IPv4_A) {
			uint32_t addr = ((uint32_t *)addrs)[i];
			uint32_t ip = ntohl(addr);
			sprintf(dest, "%d.%d.%d.%d",
				(int)(uint8_t)((ip >> 24) & 0xff),
				(int)(uint8_t)((ip >> 16) & 0xff),
				(int)(uint8_t)((ip >> 8) & 0xff),
				(int)(uint8_t)((ip)&0xff));

			pgs_session_debug(session, "[DNS] %s: %s",
					  session->cmd.dest, dest);

			bool bypass_match = pgs_acl_match_host_bypass(
				session->local->acl, dest);

			if (session->cmd.dest != NULL) {
				memcpy(raw_cmd, session->cmd.raw_cmd, 4);
				raw_cmd[3] = SOCKS5_CMD_IPV4;
				raw_cmd[4] = (ip >> 24) & 0xFF;
				raw_cmd[5] = (ip >> 16) & 0xFF;
				raw_cmd[6] = (ip >> 8) & 0xFF;
				raw_cmd[7] = ip & 0xFF;
				raw_cmd[8] = (session->cmd.port >> 8) & 0xFF;
				raw_cmd[9] = session->cmd.port & 0xFF;
			}

			if (bypass_match) {
				session->proxy = false;
				pgs_session_debug(session, "[bypass] %s(%s)",
						  session->cmd.dest, dest);
				break;
			}

		} else if (type == DNS_PTR) {
			pgs_session_debug(session, "%s: %s", session->cmd.dest,
					  ((char **)addrs)[i]);
		}
		if (raw_cmd[0] != 0) {
			pgs_socks5_cmd_free(session->cmd);
			session->cmd = socks5_cmd_parse(raw_cmd, raw_cmd_len);
		}
	}
	if (!count) {
		pgs_session_error(session, "%s: No answer (%d)",
				  session->cmd.dest, result);
	}
	session->state = DNS_RESOLVE;

	switch (session->inbound.protocol) {
	case PROTOCOL_TYPE_TCP: {
		on_socks5_handshake(session->inbound.ctx, session);
		break;
	}
	case PROTOCOL_TYPE_UDP: {
		// TODO: init outbound( udp bypass / trojan / vmess udp over tcp )
	}
	default: {
	}
	}

	/* just leave it, prevent to double free */
	session->dns_req = NULL;
}
#endif

typedef enum { FILTER_DIR_ENCODE, FILTER_DIR_DECODE } filter_direction;

static inline bool apply_filters(pgs_session_t *session, const uint8_t *msg,
				 size_t len, uint8_t **result, size_t *res_len,
				 filter_direction dir)
{
	pgs_list_node_t *cur, *next, *prev;
	pgs_filter_t *filter;
	uint8_t *input = (uint8_t *)msg;
	uint8_t *output = NULL;
	size_t ilen = len;
	size_t olen = 0;
	switch (dir) {
	case (FILTER_DIR_DECODE): {
		pgs_list_foreach_backward((session)->filters, cur, prev)
		{
			filter = (pgs_filter_t *)(cur->val);
			bool ok = filter->decode(filter->ctx, input, ilen,
						 &output, &olen);

			if (input != msg)
				free(input);

			if (!ok) {
				if (output)
					free(output);
				return false;
			}

			if (olen != 0) {
				input = output;
				ilen = olen;
			}
		}
		break;
	}
	case (FILTER_DIR_ENCODE): {
		pgs_list_foreach((session)->filters, cur, next)
		{
			filter = (pgs_filter_t *)(cur->val);
			bool ok = filter->encode(filter->ctx, input, ilen,
						 &output, &olen);

			if (input != msg)
				// from last filter output, should free it
				free(input);

			if (!ok) {
				if (output)
					free(output);
				return false;
			}

			if (olen != 0) {
				// swap buffer
				input = output;
				ilen = olen;
			}
		}
		break;
	}
	default:
		return false;
	}

	*result = input;
	*res_len = ilen;
	return true;
}

static void pgs_ping_read(void *psession)
{
	pgs_ping_session_t *ptr = (pgs_ping_session_t *)psession;
	gettimeofday(&ptr->ts_send, NULL);
	long seconds = ptr->ts_send.tv_sec - ptr->ts_start.tv_sec;
	long micros = ((seconds * 1000000) + ptr->ts_send.tv_usec -
		       ptr->ts_start.tv_usec);
	ptr->ping = micros / 1000;
	pgs_session_debug((&ptr->session), "ping: %f", ptr->ping);

	ptr->session.local->sm->server_stats[ptr->idx].connect_delay =
		ptr->ping;

	uint8_t *msg = (uint8_t *)g204_http_req;
	size_t len = strlen(g204_http_req);

	uint8_t *result = NULL;
	size_t res_len = 0;

	if (!apply_filters(&(ptr->session), msg, len, &result, &res_len,
			   FILTER_DIR_ENCODE))
		goto error;

	if (!result)
		goto error;

	size_t wlen;
	bool ok = ptr->session.outbound.write(ptr->session.outbound.ctx, result,
					      res_len, &wlen);

	if (!ok)
		goto error;

	return;

error:
	PGS_FREE_SESSION((
		&ptr->session)); /* will be called at fake local, the ping session will be freed*/
}

static bool pgs_ping_write(void *ctx, uint8_t *msg, size_t len, size_t *olen)
{
	pgs_ping_session_t *ptr = (pgs_ping_session_t *)ctx;
	*olen = len;
	gettimeofday(&ptr->ts_recv, NULL);
	// pgs_session_debug_buffer((&ptr->session), msg, len);
	long seconds = ptr->ts_recv.tv_sec - ptr->ts_start.tv_sec;
	long micros = ((seconds * 1000000) + ptr->ts_recv.tv_usec -
		       ptr->ts_start.tv_usec);
	ptr->g204 = micros / 1000;
	pgs_session_debug((&ptr->session), "g204: %f", ptr->g204);

	ptr->session.local->sm->server_stats[ptr->idx].g204_delay = ptr->g204;
	return true;
}

static void pgs_inbound_tcp_read(void *psession)
{
	pgs_session_t *session = (pgs_session_t *)psession;
	struct bufferevent *bev = session->inbound.ctx;
	struct evbuffer *ireader = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(ireader);
	uint8_t *msg = evbuffer_pullup(ireader, len);

	// apply filters
	uint8_t *result = NULL;
	size_t res_len = 0;

	if (!apply_filters(session, msg, len, &result, &res_len,
			   FILTER_DIR_ENCODE))
		goto error;

	if (!result)
		goto error;

	size_t wlen;
	bool ok = session->outbound.write(session->outbound.ctx, result,
					  res_len, &wlen);

	if (!ok)
		goto error;

	if (result != msg)
		free(result);

	evbuffer_drain(ireader, len);

	return;

error:
	PGS_FREE_SESSION(session);
}
static bool pgs_bufferevent_write(void *ctx, uint8_t *msg, size_t len,
				  size_t *olen)
{
	if (!ctx)
		return false;
	struct bufferevent *be = ctx;
	struct evbuffer *writer = bufferevent_get_output(be);
	if (evbuffer_add(writer, msg, len))
		return false;
	*olen = len;
	return true;
}
static void on_tcp_outbound_event(struct bufferevent *bev, short events,
				  void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;

	if (events & BEV_EVENT_CONNECTED) {
		pgs_session_debug(session, "%s:%d connected",
				  session->config->server_address,
				  session->config->server_port);
		// #ifndef USE_MBEDTLS
		// 		SSL *ssl = bufferevent_openssl_get_ssl(bev);
		// 		if (SSL_session_reused(ssl)) {
		// 			pgs_session_debug(session, "ssl session reused");
		// 		} else {
		// 			pgs_session_debug(session, "ssl session negotiated");
		// 		}
		// #endif
		session->outbound.ready = true;

		if (session->state != SOCKS5_PROXY) {
			pgs_session_error(session, "invalid session state");
			PGS_FREE_SESSION(session);
			return;
		}
		// manually trigger a read(cached buffer)
		return session->inbound.read(session);
	}

	if (events & BEV_EVENT_ERROR)
		pgs_session_error(session, "Error from bufferevent");
	if (events & BEV_EVENT_TIMEOUT)
		pgs_session_debug(session, "timeout: %s:%d", session->cmd.dest,
				  session->cmd.port);

	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT))
		PGS_FREE_SESSION(session);
}
static void on_tcp_outbound_read(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	struct evbuffer *reader = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(reader);
	unsigned char *msg = evbuffer_pullup(reader, len);

	uint8_t *result = NULL;
	size_t res_len = 0;

	if (!apply_filters(session, msg, len, &result, &res_len,
			   FILTER_DIR_DECODE))
		goto error;

	size_t wlen;

	if (!session->inbound.write(session->inbound.ctx, result, res_len,
				    &wlen))
		goto error;

	if (result != msg)
		free(result);

	evbuffer_drain(reader, len);

	return;
error:
	PGS_FREE_SESSION(session);
}

static bool pgs_outbound_trojanws_write(void *ctx, uint8_t *msg, size_t len,
					size_t *olen)
{
	pgs_trojan_ctx_t *tctx = (pgs_trojan_ctx_t *)ctx;
	struct bufferevent *outbev = tctx->bev;
	struct evbuffer *writer = bufferevent_get_output(outbev);

	ssize_t head_len = tctx->head_len;
	ssize_t ws_len = len;
	if (head_len > 0) {
		ws_len += head_len;
	}
	// we only need to write ws header
	// use all 0 for xor encode
	// x ^ 0 = x, so no need for extra xor
	pgs_ws_write_head_text(writer, ws_len);
	*olen = ws_len;

	if (tctx->head_len) {
		evbuffer_add(writer, tctx->head, tctx->head_len);
		tctx->head_len = 0;
	}
	evbuffer_add(writer, msg, len);
	return true;
}

static void on_trojanws_event(struct bufferevent *bev, short events, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;

	if (events & BEV_EVENT_CONNECTED) {
		pgs_config_extra_trojan_t *tconf = session->config->extra;
		pgs_session_debug(
			session,
			"trojan-ws connected, now do websocket handshake..");
		// ws conenct
		pgs_ws_req(bufferevent_get_output(bev),
			   tconf->websocket.hostname,
			   session->config->server_address,
			   session->config->server_port, tconf->websocket.path);
	}

	if (events & BEV_EVENT_ERROR)
		pgs_session_error(
			session,
			"Error from bufferevent: on_trojan_remote_event");
	if (events & BEV_EVENT_TIMEOUT)
		pgs_session_debug(session, "trojan remote timeout: %s:%d",
				  session->cmd.dest, session->cmd.port);
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
		PGS_FREE_SESSION(session);
	}
}

static void on_trojanws_read(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "remote read triggered");
	struct evbuffer *input = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(input);
	unsigned char *msg = evbuffer_pullup(input, len);
	size_t olen = 0;

	pgs_trojan_ctx_t *tctx = session->outbound.ctx;
	if (!session->outbound.ready) {
		// verify websocket handshake
		if (!strstr((const char *)msg, "\r\n\r\n"))
			return;

		if (pgs_ws_upgrade_check((const char *)msg)) {
			pgs_session_error(session, "websocket upgrade fail!");
			return on_trojanws_event(bev, BEV_EVENT_ERROR, ctx);
		} else {
			pgs_session_debug(session,
					  "websocket upgrade success!");
			//drain
			evbuffer_drain(input, len);
			session->outbound.ready = true;
			// manually trigger a read local event
			if (session->state != SOCKS5_PROXY) {
				pgs_session_error(session,
						  "invalid session state");
				PGS_FREE_SESSION(session);
				return;
			}
			// manually trigger a read(cached buffer)
			session->inbound.read(session);
		}
		return;
	} else {
		if (len < 2)
			return; // wait next read
		pgs_session_debug(session, "msg len: %d", len);
		while (len > 2) {
			pgs_ws_resp_t ws_meta;
			if (pgs_ws_parse_head(msg, len, &ws_meta)) {
				pgs_session_debug(
					session,
					"opcode: %d, payload_len: %d, header_len: %d",
					ws_meta.opcode, ws_meta.payload_len,
					ws_meta.header_len);
				// ignore opcode here

				if (!session->inbound.write(
					    session->inbound.ctx,
					    msg + ws_meta.header_len,
					    ws_meta.payload_len, &olen)) {
					goto error;
				}
				pgs_session_debug(session,
						  "write back to local: %d",
						  ws_meta.payload_len);

				if (!ws_meta.fin)
					pgs_session_debug(
						session,
						"frame to be continued..");

				evbuffer_drain(input,
					       ws_meta.header_len +
						       ws_meta.payload_len);

				len -= (ws_meta.header_len +
					ws_meta.payload_len);
				msg += (ws_meta.header_len +
					ws_meta.payload_len);
			} else {
				pgs_session_debug(
					session,
					"Failed to parse ws header, wait for more data");
				return;
			}
		}
	}
	return;
error:
	PGS_FREE_SESSION(session);
}

static bool pgs_init_udp_inbound(pgs_session_t *session, int fd)
{
	pgs_session_debug(session, "udp local read triggered");

	session->inbound.protocol = PROTOCOL_TYPE_UDP;
	session->state = SOCKS5_UDP_ASSOCIATE;
	session->proxy = true;

	const pgs_server_config_t *config =
		pgs_server_manager_get_config(session->local->sm);
	session->config = config;

	pgs_udp_ctx_t *ctx = pgs_udp_ctx_new(fd, &session->cmd);
	session->inbound.ctx = ctx;
	session->inbound.free = (void *)pgs_udp_ctx_free;
	session->inbound.read = NULL;
	session->inbound.write = NULL;

	struct sockaddr_in in_addr = { 0 };
	socklen_t in_addr_len = sizeof(struct sockaddr_in);

	ssize_t len = recvfrom(fd, ctx->cache->buffer, ctx->cache->cap, 0,
			       (struct sockaddr *)&in_addr, &in_addr_len);
	if (len == -1) {
		pgs_session_debug(session, "error: udp recvfrom");
		goto clean;
	}
	if (len == 0) {
		pgs_session_debug(session, "udp connection closed");
		goto clean;
	}
	if (len > DEFAULT_MTU) {
		pgs_session_debug(session, "mtu too small");
		goto clean;
	}
	const uint8_t *buf = ctx->cache->buffer;
	uint8_t frag = buf[2];
	if (frag != 0x00) {
		pgs_session_debug(session,
				  "fragmentation is not supported(frag: %d)",
				  frag);
		goto clean;
	}

	int addr_len = socks5_cmd_get_addr_len(buf + 3);
	if (addr_len == 0) {
		pgs_session_debug(session, "socks5: wrong atyp");
		goto clean;
	}
	size_t cmd_len = 4 + addr_len + 2;
	session->cmd = socks5_cmd_parse(buf, cmd_len);

#ifdef WITH_ACL
	if (session->local->acl != NULL) {
		bool bypass_match = pgs_acl_match_host_bypass(
			session->local->acl, session->cmd.dest);
		bool proxy_match = pgs_acl_match_host_proxy(session->local->acl,
							    session->cmd.dest);

		if (proxy_match) {
			session->proxy = true;
		}
		if (bypass_match) {
			session->proxy = false;
		}

		if (!bypass_match && !proxy_match) {
			session->dns_req = evdns_base_resolve_ipv4(
				session->local->dns_base, session->cmd.dest, 0,
				dns_cb, session);
			return true;
		}
	}
#endif
	if (!session->proxy) {
		// TODO: init udp outbound
	} else {
		// proxy udp over tcp
		// custom different write methods is good enough
	}

	return true;
clean:
	return false;
}
static bool pgs_init_tcp_inbound(pgs_session_t *session, int fd)
{
	// init inbound
	session->inbound.protocol = PROTOCOL_TYPE_TCP;

	struct bufferevent *bev = bufferevent_socket_new(
		session->local->base, fd, BEV_OPT_CLOSE_ON_FREE);
	session->inbound.ctx = bev;
	session->inbound.read = pgs_inbound_tcp_read;
	session->inbound.write = pgs_bufferevent_write;
	session->inbound.free = (void *)bufferevent_free;

	// starting to serve
	bufferevent_setcb(bev, on_socks5_handshake, NULL, on_local_event,
			  session);
	bufferevent_enable(bev, EV_READ);
	return true;
}

static bool pgs_init_bypass_udp_outbound(pgs_session_t *session)
{
	// TODO:
	return true;
}
static bool pgs_init_bypass_tcp_outbound(pgs_session_t *session)
{
	session->outbound.protocol = PROTOCOL_TYPE_TCP;
	session->outbound.ready = true;

	// init a buffer event
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	int err = evutil_make_socket_nonblocking(fd);
	if (err) {
		if (fd)
			evutil_closesocket(fd);
		return false;
	}
	int opt = 1;
	setsockopt(fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));

#ifdef __ANDROID__
	pgs_config_t *gconfig = session->local->config;
	int ret = pgs_protect_fd(fd, gconfig->android_protect_address,
				 gconfig->android_protect_port);
	if (ret != fd) {
		pgs_session_error(session, "[ANDROID] Failed to protect fd");
		return false;
	}
#endif

	struct bufferevent *bev = bufferevent_socket_new(
		session->local->base, fd,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	session->outbound.ctx = bev;
	session->outbound.free = (void *)bufferevent_free;
	session->outbound.write = pgs_bufferevent_write;

	bufferevent_setcb(bev, on_tcp_outbound_read, NULL,
			  on_tcp_outbound_event, session);

	// setup timeout and connect
	struct timeval tv = {
		.tv_sec = session->local->config->timeout,
		.tv_usec = 0,
	};
	bufferevent_set_timeouts(bev, &tv, NULL);
	// enable read event
	bufferevent_enable(bev, EV_READ);
	bufferevent_socket_connect_hostname(bev, session->local->dns_base,
					    AF_INET, session->cmd.dest,
					    session->cmd.port);

	return true;
}
static bool pgs_init_tcp_outbound(pgs_session_t *session)
{
	if (!session->proxy)
		return pgs_init_bypass_tcp_outbound(session);

	session->outbound.protocol = PROTOCOL_TYPE_TCP;
	session->outbound.ready = false;

	const char *server_type = session->config->server_type;
	if (IS_TROJAN_SERVER(server_type)) {
		pgs_config_extra_trojan_t *tconf = session->config->extra;

		// setup fd
		int fd = socket(AF_INET, SOCK_STREAM, 0);
		evutil_make_socket_nonblocking(fd);

		int opt = 1;
		setsockopt(fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));

#ifdef __ANDROID__
		pgs_config_t *gconfig = session->local->config;
		int ret = pgs_protect_fd(fd, gconfig->android_protect_address,
					 gconfig->android_protect_port);
		if (ret != fd) {
			pgs_session_error(session,
					  "[ANDROID] Failed to protect fd");
			return false;
		}
#endif
		struct bufferevent *bev;
		// setup ssl bufferevemt
		const char *sni = NULL;
		GET_TROJAN_SNI(session->config, sni);
		if (pgs_session_outbound_ssl_bev_init(
			    &bev, fd, session->local->base,
			    session->local->ssl_ctx, sni))
			return false;

		session->outbound.ctx = bev;
		session->outbound.free = (void *)bufferevent_free;

		pgs_filter_t *trojan_filter =
			pgs_filter_new(FILTER_TROJAN, session);
		pgs_list_node_t *filter_node = pgs_list_node_new(trojan_filter);
		pgs_list_add(session->filters, filter_node);

		// pgs_trojan_ctx_t *ctx = pgs_trojan_ctx_new(session);
		// if (ctx == NULL || ctx->fd == -1)
		// 	return false;
		// session->outbound.ctx = ctx;
		// session->outbound.free = (void *)pgs_trojan_ctx_free;

		// setup callbacks and write method
		if (tconf->websocket.enabled) {
			// ws
			// session->outbound.write = pgs_outbound_trojanws_write;
			// bufferevent_setcb(ctx->bev, on_trojanws_read, NULL,
			// 		  on_trojanws_event, session);
			pgs_session_error(session, "invalid server type: %s",
					  server_type);
			return false;
		}

		session->outbound.write = pgs_bufferevent_write;
		bufferevent_setcb(bev, on_tcp_outbound_read, NULL,
				  on_tcp_outbound_event, session);

		// enable read event
		bufferevent_enable(bev, EV_READ);
		// setup timeout and connect
		struct timeval tv = {
			.tv_sec = session->local->config->timeout,
			.tv_usec = 0,
		};
		bufferevent_set_timeouts(bev, &tv, NULL);
		bufferevent_socket_connect_hostname(
			bev, session->local->dns_base, AF_INET,
			session->config->server_address,
			session->config->server_port);
	} else {
		pgs_session_error(session, "invalid server type: %s",
				  server_type);
		return false;
	}
	return true;
}

static bool pgs_init_udp_outbound(pgs_session_t *session)
{
	if (!session->proxy)
		return pgs_init_bypass_udp_outbound(session);

	return true;
}

pgs_session_t *pgs_session_new(pgs_local_server_t *local,
			       const pgs_server_config_t *config)
{
	pgs_session_t *ptr = calloc(1, sizeof(pgs_session_t));
	ptr->proxy = true;

	ptr->local = local;
	if (config)
		ptr->config = config;
	else
		ptr->config = pgs_server_manager_get_config(local->sm);

	/* filters are executed in chain-like order */
	ptr->filters = pgs_list_new();
	ptr->filters->free = (void *)pgs_filter_free;

	/* ref to local.sessions */
	ptr->node = pgs_list_node_new(ptr);
	pgs_list_add(local->sessions, ptr->node);

	return ptr;
}

void pgs_session_start_tcp(pgs_session_t *session, int fd)
{
	if (!pgs_init_tcp_inbound(session, fd))
		PGS_FREE_SESSION(session);
}

void pgs_session_start_udp(pgs_session_t *session, int fd)
{
	if (!pgs_init_udp_inbound(session, fd))
		PGS_FREE_SESSION(session);
}
void pgs_session_free(pgs_session_t *session)
{
	if (!session)
		return;
	pgs_session_debug(session, "session to %s:%d closed", session->cmd.dest,
			  session->cmd.port);
#ifdef WITH_ACL
	if (session->dns_req) {
		evdns_cancel_request(session->local->dns_base,
				     session->dns_req);
	}
#endif
	if (session->outbound.free)
		session->outbound.free(session->outbound.ctx);

	if (session->inbound.free)
		session->inbound.free(session->inbound.ctx);

	if (session->filters)
		pgs_list_free(session->filters);

	pgs_socks5_cmd_free(session->cmd);

	free(session);
}

pgs_socks5_cmd_t socks5_cmd_parse(const uint8_t *cmd, size_t cmd_len)
{
	pgs_socks5_cmd_t ret = { 0 };
	ret.atype = cmd[3];

	int offset = 4;
	char *dest = NULL;

	switch (ret.atype) {
	case SOCKS5_CMD_IPV4: {
		assert(cmd_len > 8);
		dest = (char *)malloc(sizeof(char) * 32);
		sprintf(dest, "%d.%d.%d.%d", cmd[offset], cmd[offset + 1],
			cmd[offset + 2], cmd[offset + 3]);
		offset += 4;
		break;
	}
	case SOCKS5_CMD_HOSTNAME: {
		offset = 5;
		int len = cmd[4];
		assert(cmd_len > len + 4);
		dest = (char *)malloc(sizeof(char) * (len + 1));
		memcpy(dest, cmd + 5, len);
		dest[len] = '\0';
		offset += len;
		break;
	}
	case SOCKS5_CMD_IPV6: {
		assert(cmd_len > 20);
		dest = (char *)malloc(sizeof(char) * 32);
		sprintf(dest, "%x:%x:%x:%x:%x:%x:%x:%x",
			cmd[offset] << 8 | cmd[offset + 1],
			cmd[offset + 2] << 8 | cmd[offset + 3],
			cmd[offset + 4] << 8 | cmd[offset + 5],
			cmd[offset + 6] << 8 | cmd[offset + 7],
			cmd[offset + 8] << 8 | cmd[offset + 9],
			cmd[offset + 10] << 8 | cmd[offset + 11],
			cmd[offset + 12] << 8 | cmd[offset + 13],
			cmd[offset + 14] << 8 | cmd[offset + 15]);
		offset += 16;
		break;
	}
	default:
		break;
	}
	if (dest) {
		ret.dest = dest;
		ret.port = (cmd[offset] << 8) | cmd[offset + 1];
		ret.cmd_len = cmd_len;

		uint8_t *raw_cmd = (uint8_t *)malloc(cmd_len);
		memcpy(raw_cmd, cmd, cmd_len);
		ret.raw_cmd = raw_cmd;
	}
	return ret;
}

void pgs_socks5_cmd_free(pgs_socks5_cmd_t cmd)
{
	if (cmd.dest)
		free(cmd.dest);
	if (cmd.raw_cmd)
		free(cmd.raw_cmd);
}

void on_local_event(struct bufferevent *bev, short events, void *ctx)
{
	// free buffer event and related session
	pgs_session_t *session = (pgs_session_t *)ctx;
	if (events & BEV_EVENT_ERROR)
		pgs_session_error(session,
				  "Error from bufferevent: on_local_event");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR))
		PGS_FREE_SESSION(session);
}

void on_socks5_handshake(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_socks5_state state = session->state;

	struct evbuffer *output = bufferevent_get_output(bev);
	struct evbuffer *input = bufferevent_get_input(bev);

	size_t len;
	uint8_t *rdata;

	switch (state) {
	case SOCKS5_AUTH:
		len = evbuffer_get_length(input);
		rdata = evbuffer_pullup(input, len);
		if (len < 2 || rdata[0] != 0x5) {
			pgs_session_error(session, "socks5: auth");
			goto error;
		}
		evbuffer_add(output, "\x05\x00", 2);
		evbuffer_drain(input, len);
		session->state = SOCKS5_CMD;
		return;
	case SOCKS5_CMD:
		len = evbuffer_get_length(input);
		rdata = evbuffer_pullup(input, len);
		if (len < 7 || rdata[0] != 0x5 || rdata[2] != 0x0) {
			pgs_session_error(session, "socks5: cmd");
			goto error;
		}

		int addr_len = socks5_cmd_get_addr_len(rdata + 3);
		if (addr_len == 0) {
			pgs_session_error(session, "socks5: wrong atyp");
			goto error;
		}
		size_t cmdlen = 4 + addr_len + 2;
		session->cmd = socks5_cmd_parse(rdata, cmdlen);

		switch (rdata[1]) {
		case 0x01: {
			// CMD connect
			pgs_session_debug(session, "--> %s:%d",
					  session->cmd.dest, session->cmd.port);
			// socks5 response, BND.ADDR and BND.PORT should be 0
			// only the UDP ASSOCIATE command will set this,
			// e.g. using `nc -X 5 -x 127.0.0.1:1080 %h %p` to proxy the ssh connection
			evbuffer_add(output,
				     "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00",
				     10);
			evbuffer_drain(input, cmdlen);

			session->state = SOCKS5_PROXY;

#ifdef WITH_ACL
			if (session->local->acl != NULL) {
				bool bypass_match = pgs_acl_match_host_bypass(
					session->local->acl, session->cmd.dest);
				bool proxy_match = pgs_acl_match_host_proxy(
					session->local->acl, session->cmd.dest);

				if (proxy_match) {
					session->proxy = true;
				}
				if (bypass_match) {
					session->proxy = false;
				}

				if (!bypass_match && !proxy_match &&
				    session->cmd.atype == SOCKS5_CMD_HOSTNAME) {
					// this will resolve cmd.dest and modify the original raw_cmd and atype
					// after resolve, will trigger a handshake call again
					session->dns_req =
						evdns_base_resolve_ipv4(
							session->local->dns_base,
							session->cmd.dest, 0,
							dns_cb, session);
					return;
				}
			}
#endif
			if (!pgs_init_tcp_outbound(session))
				goto error;

			return;
		}
		case 0x02: // bind
		case 0x03: {
			/* CMD UDP ASSOCIATE (not a standard rfc implementation, but it works and is efficient)*/
			int port = session->local->config->local_port;
			evbuffer_add(output, "\x05\x00\x00\x01\x00\x00\x00\x00",
				     8);
			int ns_port = htons(port);
			evbuffer_add(output, &ns_port, 2);
			evbuffer_drain(input, len);
			session->state = SOCKS5_UDP_ASSOCIATE;
			return;
		}

		default:
			pgs_session_error(session,
					  "socks5: cmd not support yet");
			goto error;
		}
	case SOCKS5_PROXY:
		// if outbound is ready, check outbound type and do the rest
		if (!session->outbound.ready)
			// it will call local_read manually when outbound is ready
			return;
		if (session->inbound.read == NULL)
			goto error;
		session->inbound.read(session);
		return;

	case SOCKS5_UDP_ASSOCIATE:
		// should never hit here
	case DNS_RESOLVE: {
		if (!pgs_init_tcp_outbound(session))
			goto error;
		session->state = SOCKS5_PROXY;
		return;
	}
	default:
		break;
	}
	return;
error:
	PGS_FREE_SESSION(session);
}

/* init fd and trojan header */
pgs_trojan_ctx_t *pgs_trojan_ctx_new(pgs_session_t *session)
{
	pgs_trojan_ctx_t *ptr = malloc(sizeof(pgs_trojan_ctx_t));
	ptr->fd = 0;
	ptr->bev = NULL;

	uint8_t *pass = session->config->password;
	size_t pass_len = SHA224_LEN * 2;
	uint8_t *cmd = session->cmd.raw_cmd;
	size_t cmd_len = session->cmd.cmd_len;

	// sha224(password) + "\r\n" + cmd[1] + cmd.substr(3) + "\r\n"
	ptr->head_len = pass_len + 2 + 1 + cmd_len - 3 + 2;
	ptr->head = (char *)malloc(sizeof(char) * ptr->head_len);

	memcpy(ptr->head, pass, pass_len);
	ptr->head[pass_len] = '\r';
	ptr->head[pass_len + 1] = '\n';
	ptr->head[pass_len + 2] = cmd[1];
	memcpy(ptr->head + pass_len + 3, cmd + 3, cmd_len - 3);
	ptr->head[ptr->head_len - 2] = '\r';
	ptr->head[ptr->head_len - 1] = '\n';

	// setup fd
	ptr->fd = socket(AF_INET, SOCK_STREAM, 0);
	int err = evutil_make_socket_nonblocking(ptr->fd);
	if (err) {
		if (ptr->fd)
			evutil_closesocket(ptr->fd);
		goto error;
	}
	int opt = 1;
	setsockopt(ptr->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));

#ifdef __ANDROID__
	pgs_config_t *gconfig = session->local->config;
	int ret = pgs_protect_fd(fd, gconfig->android_protect_address,
				 gconfig->android_protect_port);
	if (ret != fd) {
		pgs_session_error(session, "[ANDROID] Failed to protect fd");
		goto error;
	}
#endif

	return ptr;

error:
	pgs_trojan_ctx_free(ptr);
	return NULL;
}
void pgs_trojan_ctx_free(pgs_trojan_ctx_t *ctx)
{
	if (!ctx)
		return;
	if (ctx->bev)
		bufferevent_free(ctx->bev);

	if (ctx->head)
		free(ctx->head);

	free(ctx);
}

pgs_ping_session_t *pgs_ping_session_new(pgs_local_server_t *local,
					 const pgs_server_config_t *config,
					 int idx)
{
	pgs_ping_session_t *ptr = malloc(sizeof(pgs_ping_session_t));
	ptr->idx = idx;

	ptr->session.cmd = socks5_cmd_parse(g204_cmd, 20);
	ptr->session.proxy = true;
	ptr->session.inbound.protocol = PROTOCOL_TYPE_TCP;
	ptr->session.state = SOCKS5_PROXY;
	ptr->session.config = config;
	ptr->session.local = local;
	ptr->session.inbound.read =
		pgs_ping_read; // remote ready (connected), send g204 bytes
	ptr->session.inbound.write = pgs_ping_write; // g204 reply
	ptr->session.inbound.ctx = ptr;
	ptr->session.filters = pgs_list_new();
	ptr->session.filters->free = (void *)pgs_filter_free;

	pgs_init_tcp_outbound(&ptr->session);

	ptr->ping = -1;
	ptr->g204 = -1;

	gettimeofday(&ptr->ts_start, NULL);

	ptr->session.node = pgs_list_node_new(ptr);
	pgs_list_add(local->sessions, ptr->session.node);
	return ptr;
}
void pgs_ping_session_free(pgs_ping_session_t *ptr)
{
	if (!ptr)
		return;
	pgs_socks5_cmd_free(ptr->session.cmd);
	if (ptr->session.outbound.free)
		ptr->session.outbound.free(ptr->session.outbound.ctx);
	free(ptr);
}

pgs_udp_ctx_t *pgs_udp_ctx_new(int fd, const pgs_socks5_cmd_t *cmd)
{
	pgs_udp_ctx_t *ptr = malloc(sizeof(pgs_udp_ctx_t));
	ptr->fd = fd;
	ptr->cmd = cmd;

	ptr->cache = pgs_buffer_new();
	pgs_buffer_ensure(ptr->cache, 2 * DEFAULT_MTU);
}

void pgs_udp_ctx_free(pgs_udp_ctx_t *ptr)
{
	if (!ptr)
		return;
	if (ptr->cache)
		pgs_buffer_free(ptr->cache);
	free(ptr);
}
