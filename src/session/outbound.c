#include "config.h"
#include "crypto.h"
#include "session/session.h"
#include "codec/codec.h"

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/util.h>

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

/*
 * init outbound fd
 */
static bool pgs_outbound_fd_init(int *fd, pgs_logger_t *logger,
				 const pgs_config_t *gconfig);

/* dns callback */
#ifdef WITH_ACL
static void outbound_dns_cb(int result, char type, int count, int ttl,
			    void *addrs, void *arg);
#endif
static bool do_outbound_init(pgs_outbound_init_param_t *param);

/*
 * bypass handlers
 */
static void on_bypass_remote_event(struct bufferevent *bev, short events,
				   void *ctx);
static void on_bypass_remote_read(struct bufferevent *bev, void *ctx);

/*
 * trojan session handlers
 */
static void on_trojan_remote_event(struct bufferevent *bev, short events,
				   void *ctx);
static void on_trojan_remote_read(struct bufferevent *bev, void *ctx);

/*
 * v2ray session handlers
 */
static void on_v2ray_remote_event(struct bufferevent *bev, short events,
				  void *ctx);
static void on_v2ray_remote_read(struct bufferevent *bev, void *ctx);

/*
 * shadowsocks session handlers
 */
static void on_ss_remote_event(struct bufferevent *bev, short events,
			       void *ctx);
static void on_ss_remote_read(struct bufferevent *bev, void *ctx);

void socks5_dest_addr_parse(const uint8_t *cmd, size_t cmd_len, uint8_t *atype,
			    char **dest_ptr, int *port)
{
	*atype = cmd[3];
	int offset = 4;
	char *dest = NULL;

	switch (*atype) {
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
	/* should free this */
	*dest_ptr = dest;
	*port = (cmd[offset] << 8) | cmd[offset + 1];
}

// trojan session context
pgs_outbound_ctx_trojan_t *
pgs_outbound_ctx_trojan_new(const uint8_t *encodepass, size_t passlen,
			    const uint8_t *cmd, size_t cmdlen)
{
	if (passlen != SHA224_LEN * 2 || cmdlen < 3)
		return NULL;
	pgs_outbound_ctx_trojan_t *ptr = (pgs_outbound_ctx_trojan_t *)malloc(
		sizeof(pgs_outbound_ctx_trojan_t));
	ptr->head_len = passlen + 2 + 1 + cmdlen - 3 + 2;
	ptr->head = (char *)malloc(sizeof(char) * ptr->head_len);

	// sha224(password) + "\r\n" + cmd[1] + cmd.substr(3) + "\r\n"
	memcpy(ptr->head, encodepass, passlen);
	ptr->head[passlen] = '\r';
	ptr->head[passlen + 1] = '\n';
	ptr->head[passlen + 2] = cmd[1];
	memcpy(ptr->head + passlen + 3, cmd + 3, cmdlen - 3);
	ptr->head[ptr->head_len - 2] = '\r';
	ptr->head[ptr->head_len - 1] = '\n';
	return ptr;
}

void pgs_outbound_ctx_trojan_free(pgs_outbound_ctx_trojan_t *ctx)
{
	if (ctx->head)
		free(ctx->head);
	ctx->head = NULL;
	free(ctx);
	ctx = NULL;
}

// vmess context
pgs_outbound_ctx_v2ray_t *pgs_outbound_ctx_v2ray_new(const uint8_t *cmd,
						     size_t cmdlen,
						     pgs_cryptor_type_t cipher)
{
	pgs_outbound_ctx_v2ray_t *ptr = (pgs_outbound_ctx_v2ray_t *)calloc(
		1, sizeof(pgs_outbound_ctx_v2ray_t));
	pgs_cryptor_type_info(cipher, &ptr->key_len, &ptr->iv_len,
			      &ptr->tag_len);
	ptr->data_enc_key = calloc(1, ptr->key_len);
	ptr->data_enc_iv = calloc(1, ptr->iv_len);
	ptr->data_dec_key = calloc(1, ptr->key_len);
	ptr->data_dec_iv = calloc(1, ptr->iv_len);
	ptr->enc_counter = 0;
	ptr->dec_counter = 0;
	ptr->cmd = cmd;
	ptr->cmdlen = cmdlen;
	ptr->cipher = cipher;

	ptr->lrbuf = pgs_buffer_new();
	ptr->lwbuf = pgs_buffer_new();
	ptr->rrbuf = pgs_buffer_new();
	ptr->rwbuf = pgs_buffer_new();

	return ptr;
}

void pgs_outbound_ctx_v2ray_free(pgs_outbound_ctx_v2ray_t *ptr)
{
	if (ptr->encryptor)
		pgs_cryptor_free(ptr->encryptor);
	if (ptr->decryptor)
		pgs_cryptor_free(ptr->decryptor);
	if (ptr->data_enc_iv)
		free(ptr->data_enc_iv);
	if (ptr->data_enc_key)
		free(ptr->data_enc_key);
	if (ptr->data_dec_iv)
		free(ptr->data_dec_iv);
	if (ptr->data_dec_key)
		free(ptr->data_dec_key);
	if (ptr->lrbuf)
		pgs_buffer_free(ptr->lrbuf);
	if (ptr->lwbuf)
		pgs_buffer_free(ptr->lwbuf);
	if (ptr->rrbuf)
		pgs_buffer_free(ptr->rrbuf);
	if (ptr->rwbuf)
		pgs_buffer_free(ptr->rwbuf);

	ptr->encryptor = NULL;
	ptr->decryptor = NULL;
	ptr->data_enc_iv = NULL;
	ptr->data_enc_key = NULL;
	ptr->data_dec_iv = NULL;
	ptr->data_dec_key = NULL;

	if (ptr)
		free(ptr);
	ptr = NULL;
}

// shadowsocks context
pgs_outbound_ctx_ss_t *pgs_outbound_ctx_ss_new(const uint8_t *cmd,
					       size_t cmd_len,
					       const uint8_t *password,
					       size_t password_len,
					       pgs_cryptor_type_t cipher)
{
	pgs_outbound_ctx_ss_t *ptr = malloc(sizeof(pgs_outbound_ctx_ss_t));
	ptr->rbuf = pgs_buffer_new();
	ptr->wbuf = pgs_buffer_new();

	pgs_cryptor_type_info(cipher, &ptr->key_len, &ptr->iv_len,
			      &ptr->tag_len);
	ptr->enc_key = malloc(ptr->key_len);
	ptr->dec_key = malloc(ptr->key_len);
	ptr->ikm = malloc(ptr->key_len);
	ptr->enc_salt = malloc(ptr->key_len);
	evp_bytes_to_key(password, password_len, ptr->ikm, ptr->key_len);

	ptr->enc_iv = calloc(1, ptr->iv_len);
	ptr->dec_iv = calloc(1, ptr->iv_len);
	ptr->cmd = cmd;
	ptr->cmd_len = cmd_len;
	ptr->cipher = cipher;
	ptr->iv_sent = false;

	ptr->aead_decode_state = READY;
	ptr->plen = 0;

	if (is_aead_cipher(cipher)) {
		// random bytes as salt
		rand_bytes(ptr->enc_salt, ptr->key_len);
		hkdf_sha1(ptr->enc_salt, ptr->key_len, ptr->ikm, ptr->key_len,
			  (const uint8_t *)SS_INFO, 9, ptr->enc_key,
			  ptr->key_len);
	} else {
		memcpy(ptr->enc_key, ptr->ikm, ptr->key_len);
		rand_bytes(ptr->enc_iv, ptr->iv_len);
	}

	ptr->encryptor =
		pgs_cryptor_new(cipher, PGS_ENCRYPT, ptr->enc_key, ptr->enc_iv);
	ptr->decryptor = NULL;

	return ptr;
}

void pgs_outbound_ctx_ss_free(pgs_outbound_ctx_ss_t *ptr)
{
	if (ptr->wbuf)
		pgs_buffer_free(ptr->wbuf);
	if (ptr->rbuf)
		pgs_buffer_free(ptr->rbuf);
	if (ptr->encryptor)
		pgs_cryptor_free(ptr->encryptor);
	if (ptr->decryptor)
		pgs_cryptor_free(ptr->decryptor);
	if (ptr->enc_iv)
		free(ptr->enc_iv);
	if (ptr->enc_key)
		free(ptr->enc_key);
	if (ptr->dec_iv)
		free(ptr->dec_iv);
	if (ptr->dec_key)
		free(ptr->dec_key);
	if (ptr->ikm)
		free(ptr->ikm);
	if (ptr->enc_salt)
		free(ptr->enc_salt);
	if (ptr)
		free(ptr);
}

// outbound

void pgs_session_outbound_free(pgs_session_outbound_t *ptr)
{
#ifdef WITH_ACL
	if (ptr->param != NULL) {
		// may be used by dns callback, update it to NULL, mark this session is terminated
		ptr->param->outbound = NULL;
	}
	if (ptr->dns_base != NULL && ptr->dns_req != NULL) {
		evdns_cancel_request(ptr->dns_base, ptr->dns_req);
	}
#endif
	if (ptr->bev) {
#ifdef USE_MBEDTLS
		bool is_be_ssl = false;
		const pgs_server_config_t *config = ptr->config;
		if (IS_V2RAY_SERVER(config->server_type)) {
			pgs_config_extra_v2ray_t *vconf =
				(pgs_config_extra_v2ray_t *)config->extra;
			if (vconf->ssl.enabled) {
				is_be_ssl = true;
			}
		}
		if (IS_TROJAN_SERVER(config->server_type)) {
			is_be_ssl = true;
		}
		int fd = bufferevent_getfd(ptr->bev);

		if (is_be_ssl) {
			mbedtls_ssl_context *ssl =
				bufferevent_mbedtls_get_ssl(ptr->bev);
			bufferevent_free(ptr->bev);
			mbedtls_ssl_free(ssl);
			free(ssl);
		} else {
			bufferevent_free(ptr->bev);
		}

		if (fd)
			evutil_closesocket(fd);
#else
		bufferevent_free(ptr->bev);
#endif
	}
	if (ptr->ctx) {
		if (IS_TROJAN_SERVER(ptr->config->server_type)) {
			pgs_outbound_ctx_trojan_free(
				(pgs_outbound_ctx_trojan_t *)ptr->ctx);
		}
		if (IS_V2RAY_SERVER(ptr->config->server_type)) {
			pgs_outbound_ctx_v2ray_free(
				(pgs_outbound_ctx_v2ray_t *)ptr->ctx);
		}
		if (IS_SHADOWSOCKS_SERVER(ptr->config->server_type)) {
			pgs_outbound_ctx_ss_free(
				(pgs_outbound_ctx_ss_t *)ptr->ctx);
		}
	}
	if (ptr->dest)
		free(ptr->dest);

	ptr->bev = NULL;
	ptr->ctx = NULL;
	ptr->dest = NULL;
	free(ptr);
	ptr = NULL;
}

bool pgs_session_trojan_outbound_init(
	pgs_session_outbound_t *ptr, pgs_logger_t *logger,
	const pgs_config_t *gconfig, const pgs_server_config_t *config,
	const uint8_t *cmd, size_t cmd_len, struct event_base *base,
	pgs_ssl_ctx_t *ssl_ctx, on_event_cb *event_cb, on_read_cb *read_cb,
	void *cb_ctx)
{
	int fd = -1;
	ptr->config = config;

	ptr->ctx =
		pgs_outbound_ctx_trojan_new(config->password, 56, cmd, cmd_len);

	// sni
	const char *sni = NULL;
	GET_TROJAN_SNI(config, sni);

	if (!pgs_outbound_fd_init(&fd, logger, gconfig))
		goto error;

	if (pgs_session_outbound_ssl_bev_init(&ptr->bev, fd, base, ssl_ctx,
					      sni))
		goto error;

	assert(event_cb && read_cb && ptr->bev);
	bufferevent_setcb(ptr->bev, read_cb, NULL, event_cb, cb_ctx);

	return true;

error:
	if (fd != -1)
		close(fd);
	return false;
}

bool pgs_session_v2ray_outbound_init(
	pgs_session_outbound_t *ptr, pgs_logger_t *logger,
	const pgs_config_t *gconfig, const pgs_server_config_t *config,
	const uint8_t *cmd, size_t cmd_len, struct event_base *base,
	pgs_ssl_ctx_t *ssl_ctx, on_event_cb *event_cb, on_read_cb *read_cb,
	void *cb_ctx)
{
	int fd = -1;
	pgs_config_extra_v2ray_t *vconf =
		(pgs_config_extra_v2ray_t *)config->extra;

	ptr->ctx = pgs_outbound_ctx_v2ray_new(cmd, cmd_len, vconf->secure);

	if (!pgs_outbound_fd_init(&fd, logger, gconfig))
		goto error;

	if (vconf->ssl.enabled) {
		// ssl + vmess
		const char *sni = NULL;
		GET_V2RAY_SNI(config, sni);
		if (pgs_session_outbound_ssl_bev_init(&ptr->bev, fd, base,
						      ssl_ctx, sni))
			goto error;
	} else {
		// raw vmess
		ptr->bev = bufferevent_socket_new(
			base, fd,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	}

	assert(event_cb && read_cb && ptr->bev);
	bufferevent_setcb(ptr->bev, read_cb, NULL, event_cb, cb_ctx);
	return true;

error:
	if (fd != -1)
		close(fd);
	return false;
}

bool pgs_session_ss_outbound_init(
	pgs_session_outbound_t *ptr, pgs_logger_t *logger,
	const pgs_config_t *gconfig, const pgs_server_config_t *config,
	const uint8_t *cmd, size_t cmd_len, struct event_base *base,
	on_event_cb *event_cb, on_read_cb *read_cb, void *cb_ctx)
{
	int fd = -1;
	pgs_config_extra_ss_t *ssconf = (pgs_config_extra_ss_t *)config->extra;

	ptr->ctx =
		pgs_outbound_ctx_ss_new(cmd, cmd_len, config->password,
					strlen((const char *)config->password),
					ssconf->method);

	if (!pgs_outbound_fd_init(&fd, logger, gconfig))
		goto error;

	ptr->bev = bufferevent_socket_new(
		base, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

	assert(event_cb && read_cb && ptr->bev);
	bufferevent_setcb(ptr->bev, read_cb, NULL, event_cb, cb_ctx);

	return true;

error:
	if (fd != -1)
		close(fd);
	return false;
}

bool pgs_session_bypass_outbound_init(pgs_session_outbound_t *ptr,
				      pgs_logger_t *logger,
				      const pgs_config_t *gconfig,
				      struct event_base *base,
				      on_event_cb *event_cb,
				      on_read_cb *read_cb, void *cb_ctx)
{
	int fd = -1;

	if (event_cb == NULL || read_cb == NULL)
		goto error;
	ptr->ctx = NULL;

	if (!pgs_outbound_fd_init(&fd, logger, gconfig))
		goto error;

	ptr->bev = bufferevent_socket_new(
		base, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	bufferevent_setcb(ptr->bev, read_cb, NULL, event_cb, cb_ctx);
	bufferevent_enable(ptr->bev, EV_READ);
	ptr->ready = true;
	ptr->bypass = true;

	return true;
error:
	if (fd != -1)
		close(fd);
	return false;
}

pgs_session_outbound_t *pgs_session_outbound_new()
{
	pgs_session_outbound_t *ptr = malloc(sizeof(pgs_session_outbound_t));
	ptr->ready = false;
	ptr->bypass = false;
	ptr->dest = NULL;
	ptr->port = 0;
	ptr->config = NULL;
	ptr->bev = NULL;
	ptr->ctx = NULL;

#ifdef WITH_ACL
	ptr->param = NULL;
	ptr->dns_base = NULL;
	ptr->dns_req = NULL;
#endif

	return ptr;
}

bool pgs_session_outbound_init(pgs_session_outbound_t *ptr, bool is_udp,
			       pgs_logger_t *logger,
			       const pgs_config_t *gconfig,
			       const pgs_server_config_t *config,
			       const uint8_t *cmd, size_t cmd_len,
			       pgs_local_server_t *local, void *cb_ctx)
{
	ptr->config = config;

	// CHECK if all zeros for UDP
	uint8_t atype = 0;
	socks5_dest_addr_parse(cmd, cmd_len, &atype, &ptr->dest, &ptr->port);

	pgs_outbound_init_param_t param = { true,    is_udp,  logger, local,
					    ptr,     gconfig, config, cmd,
					    cmd_len, cb_ctx };

#ifdef WITH_ACL
	if (local->acl != NULL) {
		bool bypass_match =
			pgs_acl_match_host_bypass(local->acl, ptr->dest);
		bool proxy_match =
			pgs_acl_match_host_proxy(local->acl, ptr->dest);

		if (!bypass_match && !proxy_match &&
		    atype == SOCKS5_CMD_HOSTNAME) {
			pgs_outbound_init_param_t *p =
				malloc(sizeof(pgs_outbound_init_param_t));
			*p = param;
			ptr->param = p;
			ptr->dns_base = local->dns_base;
			ptr->dns_req =
				evdns_base_resolve_ipv4(local->dns_base,
							ptr->dest, 0,
							outbound_dns_cb, p);

			return true;
		}

		if (proxy_match) {
			param.proxy = true;
		}
		if (bypass_match) {
			param.proxy = false;
		}
	}
#endif

	return do_outbound_init(&param);
error:
	return false;
}

// ===================================
static void on_bypass_remote_event(struct bufferevent *bev, short events,
				   void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;

	if (events & BEV_EVENT_CONNECTED) {
		on_bypass_local_read(session->inbound->bev, ctx);
	}

	if (events & BEV_EVENT_TIMEOUT)
		pgs_session_error(session, "bypass remote timeout");
	if (events & BEV_EVENT_ERROR)
		pgs_session_error(
			session,
			"Error from bufferevent: on_bypass_remote_event");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
		PGS_FREE_SESSION(session);
	}
}

static void on_bypass_remote_read(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "remote read triggered");
	struct evbuffer *input = bufferevent_get_input(bev);
	size_t data_len = evbuffer_get_length(input);
	unsigned char *data = evbuffer_pullup(input, data_len);

	if (data_len > 0) {
		struct bufferevent *inbev = session->inbound->bev;
		struct evbuffer *inboundw = bufferevent_get_output(inbev);
		evbuffer_add(inboundw, data, data_len);
		evbuffer_drain(input, data_len);
		on_session_metrics_recv(session, data_len);
	}

	return;

error:
	PGS_FREE_SESSION(session);
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
		const pgs_config_extra_trojan_t *trojanconfig = config->extra;
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
			pgs_outbound_ctx_trojan_t *trojan_s_ctx =
				session->outbound->ctx;
			session->outbound->ready = true;
			// manually trigger a read local event
			if (session->inbound->state == INBOUND_PROXY) {
				// TCP
				on_trojan_local_read(session->inbound->bev,
						     ctx);
			} else if (session->inbound->state ==
					   INBOUND_UDP_RELAY &&
				   session->inbound->udp_fd != 0) {
				if (session->inbound->rbuf_pos > 0) {
					on_udp_read_trojan(
						session->inbound->udp_rbuf,
						session->inbound->rbuf_pos,
						session);
					session->inbound->rbuf_pos = 0;
				}
			}
		}
	}
	if (events & BEV_EVENT_TIMEOUT)
		pgs_session_error(session, "trojan remote timeout");
	if (events & BEV_EVENT_ERROR)
		pgs_session_error(
			session,
			"Error from bufferevent: on_trojan_remote_event");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
		PGS_FREE_SESSION(session);
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

	size_t data_len = evbuffer_get_length(input);
	unsigned char *data = evbuffer_pullup(input, data_len);

	const pgs_server_config_t *config = session->outbound->config;
	if (config == NULL) {
		pgs_session_error(session, "current server config not found");
		goto error;
	}
	pgs_config_extra_trojan_t *trojanconf =
		(pgs_config_extra_trojan_t *)config->extra;
	if (!trojanconf->websocket.enabled) {
		// trojan-gfw
		size_t olen;
		bool ok = trojan_write_local(session, data, data_len, &olen);
		evbuffer_drain(input, data_len);
		on_session_metrics_recv(session, olen);
		if (!ok)
			goto error;
		return;
	}
	// trojan ws
	pgs_outbound_ctx_trojan_t *trojan_s_ctx = session->outbound->ctx;
	if (!session->outbound->ready) {
		if (!strstr((const char *)data, "\r\n\r\n"))
			return;

		if (pgs_ws_upgrade_check((const char *)data)) {
			pgs_session_error(session, "websocket upgrade fail!");
			on_trojan_remote_event(bev, BEV_EVENT_ERROR, ctx);
		} else {
			//drain
			evbuffer_drain(input, data_len);
			session->outbound->ready = true;
			// local buffer should have data already
			// manually trigger a read local event
			if (session->inbound->state == INBOUND_PROXY) {
				on_trojan_local_read(bev, ctx);
			} else if (session->inbound->state ==
					   INBOUND_UDP_RELAY &&
				   session->inbound->udp_fd != 0) {
				if (session->inbound->rbuf_pos > 0) {
					on_udp_read_trojan(
						session->inbound->udp_rbuf,
						session->inbound->rbuf_pos,
						session);
					session->inbound->rbuf_pos = 0;
				}
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
					size_t olen;
					bool ok = trojan_write_local(
						session,
						data + ws_meta.header_len,
						ws_meta.payload_len, &olen);
					if (!ok)
						goto error;
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

/*
 * v2ray wss session handlers
 */
static void on_v2ray_remote_event(struct bufferevent *bev, short events,
				  void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;

	if (events & BEV_EVENT_CONNECTED) {
		const pgs_server_config_t *config = session->outbound->config;
		const pgs_config_extra_v2ray_t *vconfig = config->extra;
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
			pgs_outbound_ctx_v2ray_t *v2ray_s_ctx =
				session->outbound->ctx;
			session->outbound->ready = true;
			pgs_session_debug(session, "v2ray connected");
			if (session->inbound->state == INBOUND_PROXY) {
				// TCP
				on_v2ray_local_read(session->inbound->bev, ctx);
			} else if (session->inbound->state ==
					   INBOUND_UDP_RELAY &&
				   session->inbound->udp_fd) {
				if (session->inbound->rbuf_pos > 0) {
					on_udp_read_v2ray(
						session->inbound->udp_rbuf,
						session->inbound->rbuf_pos,
						session);
					session->inbound->rbuf_pos = 0;
				}
			}
		}
	}
	if (events & BEV_EVENT_TIMEOUT)
		pgs_session_error(session, "v2ray remote timeout");
	if (events & BEV_EVENT_ERROR)
		pgs_session_error(
			session,
			"Error from bufferevent: on_v2ray_remote_event");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
		PGS_FREE_SESSION(session);
	}
}
static void on_v2ray_remote_read(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "remote read triggered");
	const pgs_server_config_t *config = session->outbound->config;
	const pgs_config_extra_v2ray_t *vconfig = config->extra;

	struct evbuffer *output = bufferevent_get_output(bev);
	struct evbuffer *input = bufferevent_get_input(bev);

	size_t data_len = evbuffer_get_length(input);
	unsigned char *data = evbuffer_pullup(input, data_len);

	pgs_outbound_ctx_v2ray_t *v2ray_s_ctx = session->outbound->ctx;

	if (!vconfig->websocket.enabled) {
		struct bufferevent *inbev = session->inbound->bev;
		struct evbuffer *inboundw = bufferevent_get_output(inbev);

		size_t olen = 0;
		if (!vmess_write_local(session, data, data_len, &olen)) {
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
	if (!session->outbound->ready) {
		if (!strstr((const char *)data, "\r\n\r\n"))
			return;

		if (pgs_ws_upgrade_check((const char *)data)) {
			pgs_session_error(session, "websocket upgrade fail!");
			on_v2ray_remote_event(bev, BEV_EVENT_ERROR, ctx);
		} else {
			evbuffer_drain(input, data_len);
			session->outbound->ready = true;
			if (session->inbound->state == INBOUND_PROXY) {
				on_v2ray_local_read(bev, ctx);
			} else if (session->inbound->state ==
					   INBOUND_UDP_RELAY &&
				   session->inbound->udp_fd != 0) {
				// UDP
				if (session->inbound->rbuf_pos > 0) {
					on_udp_read_v2ray(
						session->inbound->udp_rbuf,
						session->inbound->rbuf_pos,
						session);
					session->inbound->rbuf_pos = 0;
				}
			}
		}
	} else {
		struct bufferevent *inbev = session->inbound->bev;
		struct bufferevent *outbev = session->outbound->bev;

		struct evbuffer *outboundr = bufferevent_get_input(outbev);
		struct evbuffer *inboundw = bufferevent_get_output(inbev);

		while (data_len > 2) {
			pgs_ws_resp_t ws_meta;
			if (pgs_ws_parse_head(data, data_len, &ws_meta)) {
				pgs_session_debug(
					session,
					"ws_meta.header_len: %d, ws_meta.payload_len: %d, opcode: %d, data_len: %d",
					ws_meta.header_len, ws_meta.payload_len,
					ws_meta.opcode, data_len);
				// ignore opcode here
				if (ws_meta.opcode == 0x02) {
					// decode vmess protocol
					size_t olen = 0;
					if (!vmess_write_local(
						    session,
						    data + ws_meta.header_len,
						    ws_meta.payload_len,
						    &olen)) {
						pgs_session_error(
							session,
							"failed to decode vmess payload");
						on_v2ray_remote_event(
							bev, BEV_EVENT_ERROR,
							ctx);
						return;
					}
				}

				if (!ws_meta.fin)
					pgs_session_debug(
						session,
						"frame to be continue..");

				evbuffer_drain(outboundr,
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
				pgs_session_debug(
					session,
					"Failed to parse ws header, wait for more data");

				return;
			}
		}
	}
}

/*
 * shadowsocks
 */
static void on_ss_remote_event(struct bufferevent *bev, short events, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;

	if (events & BEV_EVENT_CONNECTED) {
		session->outbound->ready = true;
		on_ss_local_read(bev, ctx);
	}
	if (events & BEV_EVENT_TIMEOUT)
		pgs_session_error(session, "shadowsocks remote timeout");
	if (events & BEV_EVENT_ERROR)
		pgs_session_error(session,
				  "Error from bufferevent: on_ss_remote_event");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
		PGS_FREE_SESSION(session);
	}
}

static void on_ss_remote_read(struct bufferevent *bev, void *ctx)
{
	pgs_session_t *session = (pgs_session_t *)ctx;
	pgs_session_debug(session, "ss remote read triggered");
	struct evbuffer *input = bufferevent_get_input(bev);

	size_t data_len = evbuffer_get_length(input);

	if (data_len <= 0)
		return;

	unsigned char *data = evbuffer_pullup(input, data_len);

	// parse
	size_t olen = 0, clen = 0;
	bool ok =
		shadowsocks_write_local(session, data, data_len, &olen, &clen);
	if (!ok) {
		pgs_session_error(session, "failed to decode shadowsocks");
		goto error;
	}
	pgs_session_debug(session, "clen: %ld, olen: %ld", clen, olen);

	evbuffer_drain(input, clen);
	on_session_metrics_recv(session, olen);

	return;

error:
	PGS_FREE_SESSION(session);
}

static bool pgs_outbound_fd_init(int *fd, pgs_logger_t *logger,
				 const pgs_config_t *gconfig)
{
	*fd = socket(AF_INET, SOCK_STREAM, 0);
	int flag = fcntl(*fd, F_GETFL, 0);
	if (fcntl(*fd, F_SETFL, flag | O_NONBLOCK))
		return false;

#ifdef __ANDROID__
	if (gconfig->android_protect_address && gconfig->android_protect_port) {
		int sock;
		struct sockaddr_in addr = { 0 };
		sock = socket(AF_INET, SOCK_STREAM, 0);
		if (sock == -1)
			return false;

		struct timeval tv;
		tv.tv_sec = 3;
		tv.tv_usec = 0;
		setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,
			   sizeof(struct timeval));
		setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv,
			   sizeof(struct timeval));

		addr.sin_family = AF_INET;
		addr.sin_port = htons(gconfig->android_protect_port);
		if (inet_pton(AF_INET, gconfig->android_protect_address,
			      &(addr.sin_addr)) != 1) {
			close(sock);
			return false;
		}

		if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) ==
		    -1) {
			pgs_logger_error(
				logger,
				"[ANDROID] Failed to connect to protect server");
			close(sock);
			return false;
		}

		char buf[4] = { 0 };
		buf[0] = (*fd >> 24) & 0xFF;
		buf[1] = (*fd >> 16) & 0xFF;
		buf[2] = (*fd >> 8) & 0xFF;
		buf[3] = *fd & 0xFF;
		int n = write(sock, buf, 4);
		if (n != 4) {
			pgs_logger_error(
				logger,
				"[ANDROID] Failed to write to protect server");
			close(sock);
			return false;
		}

		n = read(sock, buf, 4);
		if (n != 4) {
			pgs_logger_error(
				logger,
				"[ANDROID] Failed to read from protect server");
			close(sock);
			return false;
		}
		close(sock);

		int ret = buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
		if (ret != *fd) {
			pgs_logger_error(logger,
					 "[ANDROID] Failed to protect fd");
			return false;
		}
	}
#endif

	return true;
}

#ifdef WITH_ACL
static void outbound_dns_cb(int result, char type, int count, int ttl,
			    void *addrs, void *arg)
{
	pgs_outbound_init_param_t *ctx = arg;
	int i;

	if (ctx->outbound == NULL) {
		pgs_logger_error(ctx->logger,
				 "dns callback: outbound is already freed");
		goto done;
	}

	char *dest = NULL;

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

			pgs_logger_debug(ctx->logger, "%s: %s",
					 ctx->outbound->dest, dest);

			bool bypass_match = pgs_acl_match_host_bypass(
				ctx->local->acl, dest);

			if (bypass_match) {
				ctx->proxy = false;
				if (ctx->outbound->dest != NULL) {
					free(ctx->outbound->dest);
					ctx->outbound->dest = (char *)malloc(
						sizeof(char) * 32);
					memcpy(ctx->outbound->dest, dest, 32);
				}
				break;
			}
		} else if (type == DNS_PTR) {
			pgs_logger_debug(ctx->logger, "%s: %s",
					 ctx->outbound->dest,
					 ((char **)addrs)[i]);
		}
	}
	if (!count) {
		pgs_logger_error(ctx->logger, "%s: No answer (%d)",
				 ctx->outbound->dest, result);
	}

	if (dest != NULL) {
		free(dest);
	}

	pgs_logger_debug(ctx->logger, "do_outbound_init, proxy: %d",
			 ctx->proxy);
	do_outbound_init(ctx);

done:
	if (ctx->outbound != NULL) {
		ctx->outbound->param = NULL;
		/* clear reference in session, to prevent double free */
		ctx->outbound->dns_req = NULL;
		ctx->outbound->dns_base = NULL;
	}
	free(ctx);
}
#endif

static bool do_outbound_init(pgs_outbound_init_param_t *param)
{
	if (param->outbound->dest == NULL) {
		pgs_logger_error(param->local->logger,
				 "socks5_dest_addr_parse");
		return false;
	}

	if (param->proxy || param->is_udp) {
		bool ok = false;
		if (IS_TROJAN_SERVER(param->config->server_type)) {
			ok = pgs_session_trojan_outbound_init(
				param->outbound, param->logger, param->gconfig,
				param->config, param->cmd, param->cmd_len,
				param->local->base, param->local->ssl_ctx,
				on_trojan_remote_event, on_trojan_remote_read,
				param->cb_ctx);
		} else if (IS_V2RAY_SERVER(param->config->server_type)) {
			ok = pgs_session_v2ray_outbound_init(
				param->outbound, param->logger, param->gconfig,
				param->config, param->cmd, param->cmd_len,
				param->local->base, param->local->ssl_ctx,
				on_v2ray_remote_event, on_v2ray_remote_read,
				param->cb_ctx);
		} else if (IS_SHADOWSOCKS_SERVER(param->config->server_type)) {
			ok = pgs_session_ss_outbound_init(
				param->outbound, param->logger, param->gconfig,
				param->config, param->cmd, param->cmd_len,
				param->local->base, on_ss_remote_event,
				on_ss_remote_read, param->cb_ctx);
		}
		if (!ok) {
			pgs_logger_error(param->local->logger,
					 "Failed to init outbound");
			return false;
		}

		bufferevent_enable(param->outbound->bev, EV_READ);

		PGS_OUTBOUND_SET_READ_TIMEOUT(param->outbound,
					      param->gconfig->timeout);
		bufferevent_socket_connect_hostname(
			param->outbound->bev, param->local->dns_base, AF_INET,
			param->config->server_address,
			param->config->server_port);

		pgs_logger_debug(param->local->logger, "connect: %s:%d",
				 param->config->server_address,
				 param->config->server_port);
	}
	if (!param->proxy) {
		assert(!param->is_udp);
		pgs_session_bypass_outbound_init(
			param->outbound, param->logger, param->gconfig,
			param->local->base, on_bypass_remote_event,
			on_bypass_remote_read, param->cb_ctx);

		pgs_logger_info(param->local->logger, "bypass: %s:%d",
				param->outbound->dest, param->outbound->port);

		PGS_OUTBOUND_SET_READ_TIMEOUT(param->outbound,
					      param->gconfig->timeout);
		bufferevent_socket_connect_hostname(
			param->outbound->bev, param->local->dns_base, AF_INET,
			param->outbound->dest, param->outbound->port);
	}
	return true;
}
