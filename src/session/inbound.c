#include "codec/codec.h"
#include "session/session.h"
#include "session/udp.h"

#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/buffer.h>

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

typedef struct pgs_udp_read_param_s {
	bool proxy;
	uint8_t atype;
	char *dest;
	int port;

	uint8_t *buf;
	ssize_t len;
	pgs_session_t *session;

	const pgs_server_config_t *config;
} pgs_udp_read_param_t;

/*
 * local handlers
 */
static void on_local_event(struct bufferevent *bev, short events, void *ctx);
static void on_local_read(struct bufferevent *bev, void *ctx);

/*
 * udp
  */
static int start_udp_server(const pgs_server_config_t *sconfig,
			    pgs_session_t *session, int *port);
static void on_udp_read(int fd, short event, void *ctx);
static void do_udp_read(pgs_udp_read_param_t *param);
#ifdef WITH_ACL
static void udp_dns_cb(int result, char type, int count, int ttl, void *addrs,
		       void *arg);
#endif

// functions

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
	ptr->rbuf_pos = 0;

	ptr->udp_bypass_sessions = pgs_list_new();
	ptr->udp_bypass_sessions->free = (void *)pgs_udp_relay_free;

	return ptr;
}

void pgs_session_inbound_start(pgs_session_inbound_t *inbound, void *ctx)
{
	struct bufferevent *bev = inbound->bev;

	bufferevent_setcb(bev, on_local_read, NULL, on_local_event, ctx);
	bufferevent_enable(bev, EV_READ);
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
	if (ptr->udp_bypass_sessions != NULL)
		pgs_list_free(ptr->udp_bypass_sessions);
	free(ptr);
}

/*
 * bypass
 */
void on_bypass_local_read(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;

	struct evbuffer *inboundr = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(inboundr);
	uint8_t *msg = evbuffer_pullup(inboundr, len);

	struct bufferevent *outbev = session->outbound->bev;
	struct evbuffer *outboundw = bufferevent_get_output(outbev);

	if (len > 0) {
		evbuffer_add(outboundw, msg, len);
		evbuffer_drain(inboundr, len);
		on_session_metrics_send(session, len);
	}
	return;

error:
	PGS_FREE_SESSION(session);
}

/*
 * inbound read handler
 * it will be enanled after upgraded
 * local -> encode(ws frame) -> remote
 * */
void on_trojan_local_read(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;

	pgs_outbound_ctx_trojan_t *tctx = session->outbound->ctx;

	struct evbuffer *inboundr = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(inboundr);
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
	pgs_config_extra_trojan_t *tsconf =
		(pgs_config_extra_trojan_t *)config->extra;
	if (tsconf->websocket.enabled) {
		//ws
		uint64_t head_len = tctx->head_len;
		uint64_t ws_len = len;
		if (head_len > 0) {
			ws_len += head_len;
		}
		// we only need to write ws header
		// use all 0 for xor encode
		// x ^ 0 = x, so no need for extra xor
		pgs_ws_write_head_text(wbuf, ws_len);
	}

	size_t olen;
	bool ok = trojan_write_remote(session, msg, len, &olen);
	evbuffer_drain(inboundr, len);
	on_session_metrics_send(session, olen);

	if (!ok)
		goto error;

	return;

error:
	PGS_FREE_SESSION(session);
}

void on_v2ray_local_read(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;

	pgs_session_debug(session, "write to remote");
	struct bufferevent *inbev = session->inbound->bev;
	struct bufferevent *outbev = session->outbound->bev;

	struct evbuffer *outboundw = bufferevent_get_output(outbev);
	struct evbuffer *inboundr = bufferevent_get_input(inbev);
	size_t data_len = evbuffer_get_length(inboundr);
	if (data_len <= 0)
		return;
	const uint8_t *data = evbuffer_pullup(inboundr, data_len);
	size_t olen = 0;
	bool ok = vmess_write_remote(session, data, data_len, &olen);

	evbuffer_drain(inboundr, data_len);
	on_session_metrics_send(session, olen);
	pgs_session_debug(session, "v2ray write to remote: %d", olen);
}

void on_ss_local_read(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;

	struct evbuffer *inboundr = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(inboundr);

	if (len <= 0)
		return;

	uint8_t *msg = evbuffer_pullup(inboundr, len);

	pgs_session_debug(session, "local -> encode -> remote");

	size_t olen = 0;
	bool ok = shadowsocks_write_remote(session, msg, len, &olen);
	if (!ok) {
		pgs_session_error(session, "failed to encode shadowsocks");
		goto error;
	}
	evbuffer_drain(inboundr, len);
	pgs_session_debug(session, "len: %ld, olen: %ld", len, olen);
	on_session_metrics_send(session, olen);

	return;

error:
	PGS_FREE_SESSION(session);
}

/* UDP */
void on_udp_read_trojan(const uint8_t *buf, ssize_t len, void *ctx)
{
	pgs_session_t *session = ctx;
	uint8_t *packet = NULL;

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
	size_t olen;
	bool ok = trojan_write_remote(session, packet, packet_len, &olen);
	if (!ok)
		goto error;

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
	PGS_FREE_SESSION(session);
}

void on_udp_read_v2ray(const uint8_t *buf, ssize_t len, void *ctx)
{
	pgs_session_t *session = ctx;
	pgs_outbound_ctx_v2ray_t *vctx = session->outbound->ctx;
	// store target_addr
	uint16_t addr_len = 1 + 2; // atype + port
	addr_len += pgs_get_addr_len(buf + 3);
	if (len <= (2 + 1 + addr_len)) {
		pgs_session_error(session, "invalid udp datagram");
		goto error;
	}
	uint16_t data_len =
		len - 2 - 1 - addr_len; /*RSV(2) | FRAG(1) | ADDR | DATA*/

	vctx->target_addr_len = addr_len;
	memcpy(vctx->target_addr, buf + 3, addr_len);

	size_t olen = 0;
	bool ok = vmess_write_remote(session, buf + 3 + addr_len, data_len,
				     &olen);
	if (!ok)
		goto error;

	return;

error:
	PGS_FREE_SESSION(session);
}

void on_remote_udp_read(int fd, short event, void *ctx)
{
	pgs_udp_relay_t *relay = (pgs_udp_relay_t *)ctx;
	uint8_t *udp_packet = NULL;

	if (event & EV_TIMEOUT) {
		goto done;
	}
	if (relay->session_ptr == NULL) {
		goto done;
	}

	pgs_session_t *session = (pgs_session_t *)(*relay->session_ptr);

	uint8_t *buf = relay->udp_rbuf;
	socklen_t size;
	struct sockaddr_in *server_addr = &relay->udp_server_addr;

	ssize_t len = recvfrom(fd, buf, BUFSIZE_16K, 0,
			       (struct sockaddr *)server_addr, &size);

	if (len > 0) {
		if (session->inbound->udp_fd) {
			int packet_len = relay->packet_header_len + len;
			udp_packet = malloc(packet_len);
			memcpy(udp_packet, relay->packet_header,
			       relay->packet_header_len);
			memcpy(udp_packet + relay->packet_header_len, buf, len);

			// packet with socks5 header
			ssize_t n =
				sendto(session->inbound->udp_fd, udp_packet,
				       packet_len, 0,
				       (struct sockaddr *)&session->inbound
					       ->udp_client_addr,
				       session->inbound->udp_client_addr_size);
			pgs_logger_debug(
				session->local_server->logger,
				"remote UDP read: %d, write %d to local", len,
				n);
		}
	}
	// fall through to done, now we clean the relay
done:
	if (udp_packet != NULL) {
		free(udp_packet);
		udp_packet = NULL;
	}
	pgs_list_del_val(session->inbound->udp_bypass_sessions, relay);
	return;
}

//================================== static handlers

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
		PGS_FREE_SESSION(session);
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

	size_t len;
	uint8_t *rdata;

	switch (state) {
	case INBOUND_AUTH:
		len = evbuffer_get_length(input);
		rdata = evbuffer_pullup(input, len);
		if (len < 2 || rdata[0] != 0x5) {
			pgs_session_error(session, "socks5: auth");
			goto error;
		}
		evbuffer_add(output, "\x05\x00", 2);
		evbuffer_drain(input, len);
		session->inbound->state = INBOUND_CMD;
		return;
	case INBOUND_CMD:
		len = evbuffer_get_length(input);
		rdata = evbuffer_pullup(input, len);
		if (len < 7 || rdata[0] != 0x5 || rdata[2] != 0x0) {
			pgs_session_error(session, "socks5: cmd");
			goto error;
		}

		int addr_len = pgs_get_addr_len(rdata + 3);
		if (addr_len == 0) {
			pgs_session_error(session, "socks5: wrong atyp");
			goto error;
		}
		// cache cmd
		size_t cmdlen = 4 + addr_len + 2;
		session->inbound->cmd = malloc(sizeof(uint8_t) * cmdlen);
		memcpy(session->inbound->cmd, rdata, cmdlen);

		// handle different commands
		// get current server index
		pgs_server_config_t *config = pgs_server_manager_get_config(
			session->local_server->sm);

		switch (rdata[1]) {
		case 0x01: {
			// CMD connect
			const uint8_t *cmd = session->inbound->cmd;
			// create outbound
			session->outbound = pgs_session_outbound_new();
			if (!pgs_session_outbound_init(
				    session->outbound, false,
				    session->local_server->logger,
				    session->local_server->config, config, cmd,
				    cmdlen, session->local_server, session))
				goto error;

			if (session && session->outbound) {
				const char *addr = session->outbound->dest;
				pgs_session_info(session, "--> %s:%d", addr,
						 session->outbound->port);
			}
			// socks5 response, BND.ADDR and BND.PORT should be 0
			// only the UDP ASSOCIATE command will set this,
			// e.g. using `nc -X 5 -x 127.0.0.1:1080 %h %p` to proxy the ssh connection
			evbuffer_add(output,
				     "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00",
				     10);
			evbuffer_drain(input, cmdlen);

			session->inbound->state = INBOUND_PROXY;
			return;
		}
		case 0x02: // bind
		case 0x03: {
			// CMD UDP ASSOCIATE
			session->outbound = pgs_session_outbound_new();
			if (!pgs_session_outbound_init(
				    session->outbound, true,
				    session->local_server->logger,
				    session->local_server->config, config,
				    rdata, cmdlen, session->local_server,
				    session))
				goto error;

			int port = 0;
			int err = start_udp_server(config, session, &port);
			if (err != 0 || port == 0) {
				goto error;
			}
			pgs_session_info(session, "udp server listening at: %d",
					 port);

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
	case INBOUND_PROXY:
		// if outbound is ready, check outbound type and do the rest
		assert(session->outbound != NULL);
		if (!session->outbound->ready) {
			// it will call local_read manually when ready
			return;
		}
		if (session->outbound->bypass) {
			return on_bypass_local_read(bev, ctx);
		} else {
			// check config
			const pgs_server_config_t *config =
				session->outbound->config;
			if (IS_V2RAY_SERVER(config->server_type)) {
				return on_v2ray_local_read(bev, ctx);
			} else if (IS_TROJAN_SERVER(config->server_type)) {
				return on_trojan_local_read(bev, ctx);
			} else if (IS_SHADOWSOCKS_SERVER(config->server_type)) {
				return on_ss_local_read(bev, ctx);
			}
		}
	case INBOUND_UDP_RELAY:
		// data should goes to local udp server now
		return;
	default:
		break;
	}
	return;
error:
	PGS_FREE_SESSION(session);
}

/*
 * Create UDP server for UDP ASSOCIATE
 * Returns error
 * Session should close the server fd and free the udp event when error occurred
 * */
// init udp fd for listening
static int init_udp_server_fd(const pgs_config_t *config, int *fd, int *port)
{
	int err = 0;
	struct sockaddr_in sin = { 0 };

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

static int start_udp_server(const pgs_server_config_t *config,
			    pgs_session_t *session, int *port)
{
	int err = init_udp_server_fd(session->local_server->config,
				     &session->inbound->udp_fd, port);
	if (err != 0 || port == 0) {
		// error
		pgs_session_error(session, "failed to init udp server");
		return err;
	}
	session->inbound->udp_rbuf = (uint8_t *)malloc(BUFSIZE_16K);
	session->inbound->udp_server_ev =
		event_new(session->local_server->base, session->inbound->udp_fd,
			  EV_READ | EV_PERSIST, on_udp_read, session);
	event_add(session->inbound->udp_server_ev, NULL);
	return 0;
}

static void on_udp_read(int fd, short event, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	assert(session->outbound != NULL);

	pgs_session_debug(session, "udp local read triggered");

	const pgs_server_config_t *config = session->outbound->config;

	uint8_t *buf = session->inbound->udp_rbuf;
	socklen_t *size = &session->inbound->udp_client_addr_size;
	struct sockaddr_in *client_addr = &session->inbound->udp_client_addr;

	ssize_t len = recvfrom(fd, buf, BUFSIZE_16K, 0,
			       (struct sockaddr *)client_addr, size);

	// TODO: check if the client ip is the same as the UDP ASSOCIATE IP
	// if not, we should drop the packet

	char *dest = NULL;
	int port = 0;

	if (0 == len) {
		pgs_session_warn(session, "udp connection closed");
	} else if (len > 0) { /*Max read/cache buffer size is 16K*/
		if (len <= 3) { /*FRAG is not supported now*/
			pgs_session_error(session, "invalid udp datagram");
			goto error;
		}

		uint8_t atype = buf[3];
		socks5_dest_addr_parse(buf, len, &atype, &dest, &port);

		pgs_udp_read_param_t param = { true, atype, dest,    port,
					       buf,  len,   session, config };
#ifdef WITH_ACL
		pgs_acl_t *acl = session->local_server->acl;
		if (acl != NULL) {
			bool bypass_match =
				pgs_acl_match_host_bypass(acl, dest);
			bool proxy_match = pgs_acl_match_host_proxy(acl, dest);
			if (!proxy_match && !bypass_match &&
			    atype == SOCKS5_CMD_HOSTNAME) {
				pgs_udp_read_param_t *p =
					malloc(sizeof(pgs_udp_read_param_t));
				*p = param;
				evdns_base_resolve_ipv4(
					session->local_server->dns_base, dest,
					0, udp_dns_cb, p);
				return;
			}

			if (proxy_match) {
				param.proxy = true;
			}
			if (bypass_match) {
				param.proxy = false;
			}
		}
#endif
		do_udp_read(&param);
	}
	if (dest != NULL) {
		free(dest);
	}
	return;

error:
	if (dest != NULL) {
		free(dest);
	}
	PGS_FREE_SESSION(session);
}

static void do_udp_read(pgs_udp_read_param_t *param)
{
	if (param->proxy) {
		if (!param->session->outbound->ready) {
			param->session->inbound->rbuf_pos = param->len;
			// should be called once ready
			// notice, this will lost data if client send more than one udp packet before the remote is ready
			return;
		}
		if (IS_TROJAN_SERVER(param->config->server_type)) {
			on_udp_read_trojan(param->buf, param->len,
					   param->session);
		} else if (IS_V2RAY_SERVER(param->config->server_type)) {
			on_udp_read_v2ray(param->buf, param->len,
					  param->session);
		} else if (IS_SHADOWSOCKS_SERVER(param->config->server_type)) {
			// TODO: udp relay to ss remote
		} else {
			pgs_session_error(
				param->session,
				"failed to handle udp packet: server type(%s) not supported",
				param->config->server_type);
		}
	} else {
		// for each bypass packet, create an one-time udp relay
		// will free this once recvieved data or session is destroyed
		pgs_udp_relay_t *udp_relay = pgs_udp_relay_new();
		pgs_list_add(param->session->inbound->udp_bypass_sessions,
			     pgs_list_node_new(udp_relay));

		if (udp_relay) {
			int host_len = pgs_get_addr_len(param->buf + 3);
			pgs_udp_relay_set_header(udp_relay, param->buf,
						 host_len + 4 + 2);

			int offset = 3 + host_len + 2;
			// add host_len as param
			int n = pgs_udp_relay_trigger(
#ifdef __ANDROID__
				param->session->local_server->config
					->android_protect_address,
				param->session->local_server->config
					->android_protect_port,
#endif
				udp_relay, param->dest, param->port,
				param->buf + offset, param->len - offset,
				param->session->local_server->base,
				on_remote_udp_read, param->session);
			pgs_session_info(param->session,
					 "udp bypass: %s:%d, sent: %d",
					 param->dest, param->port, n);
		}
	}
}

#ifdef WITH_ACL
static void udp_dns_cb(int result, char type, int count, int ttl, void *addrs,
		       void *arg)
{
	pgs_udp_read_param_t *ctx = arg;
	int i;

	char *dest = NULL;
	bool match;

	for (i = 0; i < count; ++i) {
		if (type == DNS_IPv4_A) {
			if (dest == NULL) {
				dest = (char *)malloc(sizeof(char) * 32);
			}
			uint32_t addr = ((uint32_t *)addrs)[i];
			uint32_t ip = ntohl(addr);
			sprintf(dest, "%d.%d.%d.%d",
				(int)(uint8_t)((ip >> 24) & 0xff),
				(int)(uint8_t)((ip >> 16) & 0xff),
				(int)(uint8_t)((ip >> 8) & 0xff),
				(int)(uint8_t)((ip)&0xff));

			pgs_session_debug(ctx->session, "%s: %s", ctx->dest,
					  dest);

			bool bypass_match = pgs_acl_match_host_bypass(
				ctx->session->local_server->acl, dest);

			if (bypass_match) {
				ctx->proxy = false;
				if (ctx->dest != NULL) {
					free(ctx->dest);
					ctx->dest = (char *)malloc(
						sizeof(char) * 32);
					memcpy(ctx->dest, dest, 32);
				}
				break;
			}
		} else if (type == DNS_PTR) {
			pgs_session_debug(ctx->session, "%s: %s", ctx->dest,
					  ((char **)addrs)[i]);
		}
	}
	if (!count) {
		pgs_session_error(ctx->session, "%s: No answer (%d)", ctx->dest,
				  result);
	}

	if (dest != NULL) {
		free(dest);
	}

	pgs_session_debug(ctx->session, "do_udp_read, proxy: %d, dest: %s",
			  ctx->proxy, ctx->dest);

	do_udp_read(ctx);

	if (ctx->dest != NULL)
		free(ctx->dest);
	free(ctx);
}
#endif
