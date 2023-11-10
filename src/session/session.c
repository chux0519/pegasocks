#include "session/session.h"
#include "config.h"
#include "session/filter.h"

#ifdef WITH_APPLET
#include "applet.h"
#endif

#ifdef __ANDROID__
#include "dns.h"
#endif

#ifndef USE_MBEDTLS
#include <openssl/ssl.h>
#endif

const unsigned char g204_cmd[] = { 0x05, 0x01, 0x00, 0x03, 0x0d, 0x77, 0x77,
				   0x77, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
				   0x65, 0x2e, 0x63, 0x6e, 0x00, 0x50 };

const char g204_http_req[] =
	"GET /generate_204 HTTP/1.1\r\nHost: www.google.cn\r\n\r\n";

const char *ws_upgrade = "HTTP/1.1 101";
const char *ws_key = "dGhlIHNhbXBsZSBub25jZQ==";
const char *ws_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

static bool pgs_init_outbound(pgs_session_t *session, pgs_protocol_t protocol);

static inline void pgs_set_nodaley(int fd)
{
#ifndef _WIN32
	int opt = 1;
	setsockopt(fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#else
	int opt = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
#endif
}

static inline void pgs_ws_req(struct evbuffer *out, const char *hostname,
			      const char *server_address, int server_port,
			      const char *path)
{
	// out, hostname, server_address, server_port, path
	evbuffer_add_printf(out, "GET %s HTTP/1.1\r\n", path);
	evbuffer_add_printf(out, "Host:%s:%d\r\n", hostname, server_port);
	evbuffer_add_printf(out, "Upgrade:websocket\r\n");
	evbuffer_add_printf(out, "Connection:upgrade\r\n");
	evbuffer_add_printf(out, "Sec-WebSocket-Key:%s\r\n", ws_key);
	evbuffer_add_printf(out, "Sec-WebSocket-Version:13\r\n");
	evbuffer_add_printf(
		out, "Origin:https://%s:%d\r\n", server_address,
		server_port); //missing this key will lead to 403 response.
	evbuffer_add_printf(out, "\r\n");
}

static inline bool pgs_ws_upgrade_check(const char *data)
{
	return strncmp(data, ws_upgrade, strlen(ws_upgrade)) != 0 ||
	       !strstr(data, ws_accept);
}

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

				pgs_socks5_cmd_free(session->cmd);
				session->cmd =
					socks5_cmd_parse(raw_cmd, raw_cmd_len);
			}

			if (bypass_match) {
				session->proxy = false;
				pgs_session_debug(session, "[bypass] %s", dest);
				break;
			}
		} else if (type == DNS_PTR) {
			pgs_session_debug(session, "%s: %s", session->cmd.dest,
					  ((char **)addrs)[i]);
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
		pgs_init_outbound(session, PROTOCOL_TYPE_UDP);
		return;
	}
	default:
		break;
	}

	/* just leave it, prevent to double free */
	session->dns_req = NULL;
}
#endif

static inline int apply_filters(pgs_session_t *session, const uint8_t *msg,
				size_t len, uint8_t **result, size_t *res_len,
				size_t *clen, pgs_filter_direction dir)
{
	pgs_list_node_t *cur, *next, *prev;
	pgs_filter_t *filter;
	uint8_t *input = (uint8_t *)msg;
	uint8_t *output = NULL;
	size_t ilen = len;
	size_t olen = 0;
	int status = FILTER_SUCCESS;
	switch (dir) {
	case (FILTER_DIR_DECODE): {
		pgs_list_foreach_backward((session)->filters, cur, prev)
		{
			filter = (pgs_filter_t *)(cur->val);
			status = filter->decode(filter->ctx, input, ilen,
						&output, &olen, clen);
			switch (status) {
			case (FILTER_FAIL):
				if (output)
					free(output);
				return status;
			case FILTER_SKIP:
				continue;
			case (FILTER_NEED_MORE_DATA):
			case (FILTER_SUCCESS):
			default:
				break;
			}
			if (input != msg)
				free(input);

			input = output;
			ilen = olen;
		}
		break;
	}
	case (FILTER_DIR_ENCODE): {
		pgs_list_foreach((session)->filters, cur, next)
		{
			filter = (pgs_filter_t *)(cur->val);
			status = filter->encode(filter->ctx, input, ilen,
						&output, &olen);

			switch (status) {
			case (FILTER_FAIL):
				if (output)
					free(output);
				return status;
			case FILTER_SKIP:
				continue;
			case (FILTER_NEED_MORE_DATA):
			case (FILTER_SUCCESS):
			default:
				break;
			}

			if (input != msg)
				// from last filter output, should free it
				free(input);

			// swap buffer
			input = output;
			ilen = olen;
		}
		break;
	}
	default:
		return FILTER_FAIL;
	}

	*result = input;
	*res_len = ilen;
	return status;
}

void on_bypass_udp_read(int fd, short event, void *ctx)
{
	pgs_session_t *session = ctx;
	pgs_udp_relay_ctx_t *uctx = session->outbound.ctx;

	if (event & EV_TIMEOUT) {
		goto done;
	}

	ssize_t len =
		recvfrom(fd, uctx->buf->buffer, uctx->buf->cap, 0,
			 (struct sockaddr *)&uctx->in_addr, &uctx->in_addr_len);

	if (len == -1) {
		pgs_session_debug(session, "error: udp recvfrom");
		goto done;
	}
	if (len == 0) {
		pgs_session_debug(session, "udp connection closed");
		goto done;
	}
	if (len > DEFAULT_MTU) {
		pgs_session_debug(session, "mtu too small");
		goto done;
	}

	size_t wlen;
	session->inbound.write(session->inbound.ctx, uctx->buf->buffer, len,
			       &wlen);

	// fall through to done, now we clean the relay
done:
	PGS_FREE_SESSION(session);
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
	size_t read_len = 0;

	int status = apply_filters(&(ptr->session), msg, len, &result, &res_len,
				   &read_len, FILTER_DIR_ENCODE);
	switch (status) {
	case FILTER_FAIL:
		if (result)
			free(result);
		goto error;
	case FILTER_NEED_MORE_DATA:
		return;
	case FILTER_SUCCESS:
	default:
		break;
	}

	if (!result)
		goto error;

	size_t wlen;
	bool ok = ptr->session.outbound.write(ptr->session.outbound.ctx, result,
					      res_len, &wlen);

	if (result && result != msg)
		free(result);

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
#ifdef WITH_APPLET
	pgs_tray_update();
#endif

	return false; /* terminate */
}

static bool pgs_inbound_udp_write(void *pctx, uint8_t *msg, size_t len,
				  size_t *olen)
{
	/**
	 * SOCKS5 UDP Response
     * +----+------+------+----------+----------+----------+
     * |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
     * +----+------+------+----------+----------+----------+
     * | 2  |  1   |  1   | Variable |    2     | Variable |
     * +----+------+------+----------+----------+----------+
	 */
	pgs_udp_ctx_t *ctx = pctx;
	size_t size = ctx->cmd->cmd_len + len;
	uint8_t *buf = malloc(sizeof(uint8_t) * size);
	buf[0] = 0x00; // RSV
	buf[1] = 0x00; // RSV
	buf[2] = 0x00; // FRAG

	memcpy(buf + 3, ctx->cmd->raw_cmd + 3, ctx->cmd->cmd_len - 3);

	memcpy(buf + ctx->cmd->cmd_len, msg, len);

	int n = sendto(ctx->fd, buf, size, 0, (struct sockaddr *)&ctx->in_addr,
		       ctx->in_addr_len);

	free(buf);

	return false; /* close this session */
}

static void pgs_inbound_udp_read(void *psession)
{
	pgs_session_t *session = (pgs_session_t *)psession;
	pgs_udp_ctx_t *ctx = session->inbound.ctx;

	size_t len = ctx->cache_len;
	uint8_t *msg = ctx->cache->buffer;
	if (len == 0)
		return;

	uint8_t *result = NULL;
	size_t res_len = 0;
	size_t _ = 0;

	int status = apply_filters(session, msg, len, &result, &res_len, &_,
				   FILTER_DIR_ENCODE);
	switch (status) {
	case FILTER_FAIL:
		goto error;
	case FILTER_NEED_MORE_DATA:
		return;
	case FILTER_SUCCESS:
	default:
		break;
	}

	if (!result)
		goto error;

	size_t wlen;
	bool ok = session->outbound.write(session->outbound.ctx, result,
					  res_len, &wlen);

	if (!ok)
		goto error;

	if (result != msg)
		free(result);

	return;

error:
	PGS_FREE_SESSION(session);
}

static void pgs_inbound_tcp_read(void *psession)
{
	pgs_session_t *session = (pgs_session_t *)psession;
	struct bufferevent *bev = session->inbound.ctx;
	struct evbuffer *ireader = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(ireader);
	uint8_t *msg = evbuffer_pullup(ireader, len);

	if (len == 0)
		return;

	// apply filters
	uint8_t *result = NULL;
	size_t res_len = 0;
	size_t _ = 0;

	int status = apply_filters(session, msg, len, &result, &res_len, &_,
				   FILTER_DIR_ENCODE);
	switch (status) {
	case FILTER_FAIL:
		goto error;
	case FILTER_NEED_MORE_DATA:
		return;
	case FILTER_SUCCESS:
	default:
		break;
	}

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

static bool pgs_udp_relay_write(void *arg, uint8_t *msg, size_t len,
				size_t *olen)
{
	if (!arg)
		return false;
	pgs_udp_relay_ctx_t *ctx = arg;

	ssize_t n = sendto(ctx->fd, msg, len, 0,
			   (struct sockaddr *)&ctx->in_addr, ctx->in_addr_len);
	if (n == -1)
		return false;
	*olen = n;
	return true;
}

static void on_ws_outbound_event(struct bufferevent *bev, short events,
				 void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;

	if (events & BEV_EVENT_CONNECTED) {
		pgs_session_debug(session, "%s:%d connected",
				  session->config->server_address,
				  session->config->server_port);

		const char *hostname = NULL;
		const char *path = NULL;
		if (IS_TROJAN_SERVER(session->config->server_type)) {
			pgs_config_extra_trojan_t *conf =
				session->config->extra;
			hostname = conf->websocket.hostname;
			path = conf->websocket.path;

		} else if (IS_V2RAY_SERVER(session->config->server_type)) {
			pgs_config_extra_v2ray_t *conf = session->config->extra;
			hostname = conf->websocket.hostname;
			path = conf->websocket.path;
		}
		if (hostname && path)
			pgs_ws_req(bufferevent_get_output(bev), hostname,
				   session->config->server_address,
				   session->config->server_port, path);
		else
			PGS_FREE_SESSION(session);
	}

	if (events & BEV_EVENT_ERROR)
		pgs_session_error(session, "Error from bufferevent");
	if (events & BEV_EVENT_TIMEOUT)
		pgs_session_debug(session, "timeout: %s:%d", session->cmd.dest,
				  session->cmd.port);

	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT))
		PGS_FREE_SESSION(session);
}

static void on_ws_outbound_read(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;

	struct evbuffer *reader = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(reader);
	unsigned char *msg = evbuffer_pullup(reader, len);
	size_t olen = 0;

	pgs_trojan_ctx_t *tctx = session->outbound.ctx;
	if (!session->outbound.ready) {
		// verify websocket handshake
		if (!strstr((const char *)msg, "\r\n\r\n"))
			return;

		if (pgs_ws_upgrade_check((const char *)msg)) {
			pgs_session_error(session, "websocket upgrade fail!");
			return on_ws_outbound_event(bev, BEV_EVENT_ERROR, ctx);
		} else {
			pgs_session_debug(session,
					  "websocket upgrade success!");
			//drain
			evbuffer_drain(reader, len);
			session->outbound.ready = true;
			// manually trigger a read local event
			if (session->state != SOCKS5_PROXY) {
				pgs_session_error(session,
						  "invalid session state");
				PGS_FREE_SESSION(session);
				return;
			}

			session->inbound.read(session);
		}
		return;
	} else {
		size_t remain_len = len;
		while (remain_len > 2) {
			uint8_t *result = NULL;
			size_t res_len = 0;
			size_t read_len = 0;

			int status = apply_filters(session, msg, remain_len,
						   &result, &res_len, &read_len,
						   FILTER_DIR_DECODE);

			switch (status) {
			case FILTER_FAIL:
				goto error;
			case FILTER_NEED_MORE_DATA:
				return;
			case FILTER_SKIP:
			case FILTER_SUCCESS:
			default:
				break;
			}

			size_t wlen;

			bool ok = session->inbound.write(
				session->inbound.ctx, result, res_len, &wlen);
			if (result != msg)
				free(result);

			if (!ok)
				goto error;

			evbuffer_drain(reader, read_len);
			remain_len -= read_len;
			msg += read_len;
		}
	}
	return;
error:
	PGS_FREE_SESSION(session);
}

static void on_tcp_outbound_event(struct bufferevent *bev, short events,
				  void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;

	if (events & BEV_EVENT_CONNECTED) {
		if (!session->proxy) {
			pgs_session_debug(session, "%s:%d connected",
					  session->cmd.dest, session->cmd.port);
		} else {
			pgs_session_debug(session, "%s:%d connected",
					  session->config->server_address,
					  session->config->server_port);
		}

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
	size_t read_len = len; /* non-zero */

	int status = apply_filters(session, msg, len, &result, &res_len,
				   &read_len, FILTER_DIR_DECODE);
	switch (status) {
	case FILTER_FAIL:
		goto error;
	case FILTER_NEED_MORE_DATA:
		pgs_session_debug(
			session,
			"need more data! msg len: %d, result: %p, res_len: %d, read_len: %d",
			len, result, res_len, read_len);
		// should fall through and write out exists buffer
		break;
	case FILTER_SUCCESS:
		pgs_session_debug(
			session,
			"success! msg len: %d, result: %p, res_len: %d, read_len: %d",
			len, result, res_len, read_len);
	default:
		break;
	}

	size_t wlen;

	bool ok = session->inbound.write(session->inbound.ctx, result, res_len,
					 &wlen);
	if (result != msg)
		free(result);

	if (!ok)
		goto error;

	evbuffer_drain(reader, read_len);

	return;
error:
	PGS_FREE_SESSION(session);
}

static bool pgs_init_udp_inbound(pgs_session_t *session, int fd)
{
	pgs_session_debug(session, "udp local read triggered");

	session->inbound.protocol = PROTOCOL_TYPE_UDP;
	session->state = SOCKS5_PROXY;
	session->proxy = true;

	const pgs_server_config_t *config =
		pgs_server_manager_get_config(session->local->sm);
	session->config = config;

	pgs_udp_ctx_t *ctx = pgs_udp_ctx_new(fd, &session->cmd);
	session->inbound.ctx = ctx;
	session->inbound.free = (void *)pgs_udp_ctx_free;
	session->inbound.read = pgs_inbound_udp_read;
	session->inbound.write = pgs_inbound_udp_write;

	ssize_t len =
		recvfrom(fd, ctx->cache->buffer, ctx->cache->cap, 0,
			 (struct sockaddr *)&ctx->in_addr, &ctx->in_addr_len);
	ctx->cache_len = len;

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
	pgs_session_debug(session, "udp -> %s:%d", session->cmd.dest,
			  session->cmd.port);

	// since dns could modify the cmd_len, we move the data to the begining
	memmove(ctx->cache->buffer, ctx->cache->buffer + cmd_len,
		ctx->cache_len - cmd_len);
	ctx->cache_len -= cmd_len;
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

		if (!bypass_match && !proxy_match &&
		    session->cmd.atype == SOCKS5_CMD_HOSTNAME) {
			session->dns_req = evdns_base_resolve_ipv4(
				session->local->dns_base, session->cmd.dest, 0,
				dns_cb, session);
			return true;
		}
	}
#endif

	return pgs_init_outbound(session, PROTOCOL_TYPE_UDP);
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
	session->outbound.protocol = PROTOCOL_TYPE_UDP;
	session->outbound.ready = true;
	session->outbound.ctx = pgs_udp_relay_ctx_new(session);
	session->outbound.free = (void *)pgs_udp_relay_ctx_free;
	session->outbound.write = (void *)pgs_udp_relay_write;

	// will read from cache and to a remote write
	session->inbound.read(session);

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
	pgs_set_nodaley(fd);
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
static bool pgs_init_outbound(pgs_session_t *session, pgs_protocol_t protocol)
{
	if (!session->proxy) {
		switch (protocol) {
		case (PROTOCOL_TYPE_TCP):
			return pgs_init_bypass_tcp_outbound(session);
		case (PROTOCOL_TYPE_UDP):
			return pgs_init_bypass_udp_outbound(
				session); /* UDP bypass */
		default:
			return false;
		}
	}
	session->outbound.protocol = protocol; /* UDP indicates udp over tcp */
	session->outbound.ready = false;

	const char *server_type = session->config->server_type;
	if (IS_TROJAN_SERVER(server_type)) {
		pgs_config_extra_trojan_t *tconf = session->config->extra;

		// setup fd
		int fd = socket(AF_INET, SOCK_STREAM, 0);
		evutil_make_socket_nonblocking(fd);
		pgs_set_nodaley(fd);
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

		if (protocol == PROTOCOL_TYPE_UDP) {
			pgs_filter_t *tr_udp_filter =
				pgs_filter_new(FITLER_TROJAN_UDP, session);
			pgs_list_node_t *node =
				pgs_list_node_new(tr_udp_filter);
			pgs_list_add(session->filters, node);
		}

		pgs_filter_t *trojan_filter =
			pgs_filter_new(FILTER_TROJAN, session);
		pgs_list_node_t *filter_node = pgs_list_node_new(trojan_filter);
		pgs_list_add(session->filters, filter_node);

		bufferevent_setcb(bev, on_tcp_outbound_read, NULL,
				  on_tcp_outbound_event, session);
		if (tconf->websocket.enabled) {
			// ws
			pgs_filter_t *wsfilter =
				pgs_filter_new(FITLER_WEBSOCKET, session);
			pgs_list_node_t *wsfilter_node =
				pgs_list_node_new(wsfilter);
			pgs_list_add(session->filters, wsfilter_node);

			bufferevent_setcb(bev, on_ws_outbound_read, NULL,
					  on_ws_outbound_event, session);
		}

		session->outbound.write = pgs_bufferevent_write;

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
	} else if (IS_SHADOWSOCKS_SERVER(server_type)) {
		pgs_config_extra_ss_t *ssconf = session->config->extra;

		// setup fd
		int fd = socket(AF_INET, SOCK_STREAM, 0);
		evutil_make_socket_nonblocking(fd);
		pgs_set_nodaley(fd);
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
		struct bufferevent *bev = bufferevent_socket_new(
			session->local->base, fd,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

		session->outbound.ctx = bev;
		session->outbound.free = (void *)bufferevent_free;

		if (protocol == PROTOCOL_TYPE_UDP) {
			pgs_session_error(session, "UDP not supported yet: %s",
					  server_type);
			return false;
		}

		pgs_filter_t *ss_filter = pgs_filter_new(FILTER_SS, session);
		pgs_list_node_t *filter_node = pgs_list_node_new(ss_filter);
		pgs_list_add(session->filters, filter_node);

		bufferevent_setcb(bev, on_tcp_outbound_read, NULL,
				  on_tcp_outbound_event, session);

		session->outbound.write = pgs_bufferevent_write;

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
	if (session->cmd.dest != NULL && session->cmd.port != 0)
		pgs_session_debug(session, "session to %s:%d closed",
				  session->cmd.dest, session->cmd.port);
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
	struct evbuffer *output = bufferevent_get_output(bev);
	struct evbuffer *input = bufferevent_get_input(bev);

	size_t len;
	uint8_t *rdata;

socks5:
	switch (session->state) {
	case SOCKS5_AUTH:
		len = evbuffer_get_length(input);
		rdata = evbuffer_pullup(input, len);
		if (len < 2 || rdata[0] != 0x5) {
			pgs_session_error(session, "socks5: auth");
			goto error;
		}
		uint8_t nmthods = rdata[1];
		size_t rlen = 1 + 1 + nmthods;
		evbuffer_add(output, "\x05\x00", 2);
		// may carry more data
		evbuffer_drain(input, rlen);
		session->state = SOCKS5_CMD;
		if (len > rlen)
			goto socks5;
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
			if (!pgs_init_outbound(session, PROTOCOL_TYPE_TCP))
				goto error;

			return;
		}
		case 0x02: // bind
		case 0x03: {
			/* CMD UDP ASSOCIATE (not a standard rfc implementation, but it works and is efficient)*/
			int port = session->local->config->local_port;
			evbuffer_add(
				output,
				"\x05\x00\x00\x01\x7f\x00\x00\x01" /* 127.0.0.1 */,
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
		// should never hit
		goto error;
	case DNS_RESOLVE: {
		if (!pgs_init_outbound(session, PROTOCOL_TYPE_TCP))
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
	pgs_set_nodaley(ptr->fd);

#ifdef __ANDROID__
	pgs_config_t *gconfig = session->local->config;
	int ret = pgs_protect_fd(ptr->fd, gconfig->android_protect_address,
				 gconfig->android_protect_port);
	if (ret != ptr->fd) {
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

	pgs_init_outbound(&ptr->session, PROTOCOL_TYPE_TCP);

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

	if (ptr->session.filters)
		pgs_list_free(ptr->session.filters);
	free(ptr);
}

pgs_udp_ctx_t *pgs_udp_ctx_new(int fd, const pgs_socks5_cmd_t *cmd)
{
	pgs_udp_ctx_t *ptr = malloc(sizeof(pgs_udp_ctx_t));
	ptr->fd = fd;
	ptr->cmd = cmd;

	ptr->cache = pgs_buffer_new();
	pgs_buffer_ensure(ptr->cache, 2 * DEFAULT_MTU);

	ptr->in_addr = (struct sockaddr_in){ 0 };
	ptr->in_addr_len = sizeof(struct sockaddr_in);

	return ptr;
}

void pgs_udp_ctx_free(pgs_udp_ctx_t *ptr)
{
	if (!ptr)
		return;
	if (ptr->cache)
		pgs_buffer_free(ptr->cache);
	/* keep the fd, it's the ufd */
	free(ptr);
}

pgs_udp_relay_ctx_t *pgs_udp_relay_ctx_new(pgs_session_t *session)
{
	pgs_udp_relay_ctx_t *ptr = malloc(sizeof(pgs_udp_ctx_t));

	ptr->buf = pgs_buffer_new();
	pgs_buffer_ensure(ptr->buf, 2 * DEFAULT_MTU);

	ptr->fd = socket(AF_INET, SOCK_DGRAM, 0);

	evutil_make_socket_nonblocking(ptr->fd);

#ifdef __ANDROID__
	pgs_config_t *gconfig = session->local->config;
	int ret = pgs_protect_fd(ptr->fd, gconfig->android_protect_address,
				 gconfig->android_protect_port);
	if (ret != ptr->fd) {
		pgs_session_error(session, "[ANDROID] Failed to protect fd");
		goto error;
	}
#endif

	ptr->in_addr = (struct sockaddr_in){ 0 };
	ptr->in_addr_len = sizeof(struct sockaddr_in);

	ptr->udp_ev =
		event_new(session->local->base, ptr->fd, EV_READ | EV_TIMEOUT,
			  on_bypass_udp_read, session);

	struct timeval tv = {
		.tv_sec = session->local->config->timeout,
		.tv_usec = 0,
	};
	event_add(ptr->udp_ev, &tv);

	ptr->in_addr.sin_family = AF_INET;
	inet_pton(AF_INET, session->cmd.dest, &ptr->in_addr.sin_addr);
	ptr->in_addr.sin_port = htons(session->cmd.port);

	return ptr;

error:
	if (!ptr)
		return NULL;
	if (ptr->fd)
		evutil_closesocket(ptr->fd);
	if (ptr)
		free(ptr);
	return NULL;
}

void pgs_udp_relay_ctx_free(pgs_udp_relay_ctx_t *ptr)
{
	if (!ptr)
		return;
	if (ptr->buf)
		pgs_buffer_free(ptr->buf);
	if (ptr->udp_ev) {
		event_del(ptr->udp_ev);
		event_free(ptr->udp_ev);
	}
	if (ptr->fd)
		evutil_closesocket(ptr->fd);
	if (ptr)
		free(ptr);
}
