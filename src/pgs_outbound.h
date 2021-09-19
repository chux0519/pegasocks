#ifndef _PGS_OUTBOUND
#define _PGS_OUTBOUND

#include "pgs_acl.h"
#include "pgs_config.h"
#include "pgs_crypto.h"

#include <stdint.h>
#include <stdbool.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>

typedef struct pgs_session_outbound_cbs_s {
	on_event_cb *on_trojan_remote_event;
	on_event_cb *on_v2ray_remote_event;
	on_event_cb *on_bypass_remote_event;
	on_read_cb *on_trojan_remote_read;
	on_read_cb *on_v2ray_remote_read;
	on_read_cb *on_bypass_remote_read;
	on_udp_read_cb *on_bypass_remote_udp_read;
} pgs_session_outbound_cbs_t;

typedef struct pgs_session_outbound_s {
	bool ready;
	bool bypass;

	struct bufferevent *bev;
	const pgs_server_config_t *config;
	char *dest;
	int port;
	void *ctx;
} pgs_session_outbound_t;

typedef struct pgs_trojansession_ctx_s {
	// sha224(password) + "\r\n" + cmd[1] + cmd.substr(3) + "\r\n"
	char *head;
	uint64_t head_len;
} pgs_trojansession_ctx_t;

typedef struct pgs_vmess_resp_s {
	uint8_t v;
	uint8_t opt;
	uint8_t cmd;
	uint8_t m;
} pgs_vmess_resp_t;

typedef struct pgs_vmess_ctx_s {
	// for aes codec
	char iv[AES_128_CFB_IV_LEN];
	char key[AES_128_CFB_KEY_LEN];
	char riv[AES_128_CFB_IV_LEN];
	char rkey[AES_128_CFB_KEY_LEN];
	uint8_t local_rbuf[BUFSIZE_16K];
	uint8_t local_wbuf[BUFSIZE_16K];
	uint8_t remote_rbuf[BUFSIZE_16K];
	uint8_t remote_wbuf[BUFSIZE_16K];
	uint8_t target_addr[BUFSIZE_512]; /*atype(1) | addr | port(2)*/
	// for request header
	const uint8_t *cmd;
	uint64_t cmdlen;
	bool header_sent;
	// for resp header
	bool header_recved;
	pgs_vmess_resp_t resp_meta;
	uint64_t resp_len;
	uint64_t target_addr_len;
	uint64_t remote_rbuf_pos;
	uint32_t resp_hash;
	pgs_base_cryptor_t *encryptor;
	pgs_base_cryptor_t *decryptor;
	pgs_v2ray_secure_t secure;
} pgs_vmess_ctx_t;

static inline int pgs_get_addr_len(const uint8_t *data)
{
	switch (data[0] /*atype*/) {
	case 0x01:
		// IPv4
		return 4;
	case 0x03:
		return 1 + data[1];
	case 0x04:
		// IPv6
		return 16;
	default:
		break;
	}
	return 0;
}

static void socks5_dest_addr_parse(const uint8_t *cmd, uint64_t cmd_len,
				   pgs_acl_t *acl, bool *proxy, char **dest_ptr,
				   int *port)
{
	int atype = cmd[3];
	int offset = 4;
	char *dest = NULL;

	switch (atype) {
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
	*dest_ptr = dest;
	*port = (cmd[offset] << 8) | cmd[offset + 1];
#ifdef WITH_ACL
	if (acl != NULL) {
		bool match = pgs_acl_match_host(acl, dest);
		if (!match && atype == SOCKS5_CMD_HOSTNAME) {
			// TODO: reolve the DNS and match the ip again
		}
		if (pgs_acl_get_mode(acl) == PROXY_ALL_BYPASS_LIST) {
			*proxy = !match;
		} else if (pgs_acl_get_mode(acl) == BYPASS_ALL_PROXY_LIST) {
			*proxy = match;
		}
	}
#endif
}

// trojan session context
static pgs_trojansession_ctx_t *
pgs_trojansession_ctx_new(const uint8_t *encodepass, uint64_t passlen,
			  const uint8_t *cmd, uint64_t cmdlen)
{
	if (passlen != SHA224_LEN * 2 || cmdlen < 3)
		return NULL;
	pgs_trojansession_ctx_t *ptr = (pgs_trojansession_ctx_t *)malloc(
		sizeof(pgs_trojansession_ctx_t));
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

static void pgs_trojansession_ctx_free(pgs_trojansession_ctx_t *ctx)
{
	if (ctx->head)
		free(ctx->head);
	ctx->head = NULL;
	free(ctx);
	ctx = NULL;
}

// vmess context
static pgs_vmess_ctx_t *pgs_vmess_ctx_new(const uint8_t *cmd, uint64_t cmdlen,
					  pgs_v2ray_secure_t secure)
{
	pgs_vmess_ctx_t *ptr =
		(pgs_vmess_ctx_t *)malloc(sizeof(pgs_vmess_ctx_t));

	memzero(ptr->local_rbuf, BUFSIZE_16K);
	memzero(ptr->local_wbuf, BUFSIZE_16K);
	memzero(ptr->remote_rbuf, BUFSIZE_16K);
	memzero(ptr->remote_wbuf, BUFSIZE_16K);
	ptr->cmd = cmd;
	ptr->cmdlen = cmdlen;
	ptr->header_sent = false;
	ptr->header_recved = false;
	memzero(&ptr->resp_meta, sizeof(pgs_vmess_resp_t));
	ptr->resp_len = 0;
	ptr->target_addr_len = 0;
	ptr->remote_rbuf_pos = 0;
	ptr->resp_hash = 0;
	ptr->encryptor = NULL;
	ptr->decryptor = NULL;
	ptr->secure = secure;

	return ptr;
}

static void pgs_vmess_ctx_free(pgs_vmess_ctx_t *ptr)
{
	if (ptr->encryptor) {
		pgs_cryptor_free(ptr->secure, ptr->encryptor);
	}
	if (ptr->decryptor) {
		pgs_cryptor_free(ptr->secure, ptr->decryptor);
	}
	ptr->encryptor = NULL;
	ptr->decryptor = NULL;
	if (ptr)
		free(ptr);
	ptr = NULL;
}

// outbound

static void pgs_session_outbound_free(pgs_session_outbound_t *ptr)
{
	if (ptr->bev)
		bufferevent_free(ptr->bev);
	if (ptr->ctx) {
		if (IS_TROJAN_SERVER(ptr->config->server_type)) {
			pgs_trojansession_ctx_free(
				(pgs_trojansession_ctx_t *)ptr->ctx);
		}
		if (IS_V2RAY_SERVER(ptr->config->server_type)) {
			pgs_vmess_ctx_free((pgs_vmess_ctx_t *)ptr->ctx);
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

static bool pgs_session_trojan_outbound_init(
	pgs_session_outbound_t *ptr, const pgs_server_config_t *config,
	const uint8_t *cmd, uint64_t cmd_len, struct event_base *base,
	on_event_cb *event_cb, on_read_cb *read_cb, void *cb_ctx)
{
	ptr->config = config;

	ptr->ctx =
		pgs_trojansession_ctx_new(config->password, 56, cmd, cmd_len);

	// sni
	const char *sni = config->server_address;
	pgs_trojanserver_config_t *tconf =
		(pgs_trojanserver_config_t *)config->extra;
	if (tconf->ssl.sni != NULL) {
		sni = tconf->ssl.sni;
	}
	if (pgs_session_outbound_ssl_bev_init(&ptr->bev, base, tconf->ssl_ctx,
					      sni))
		goto error;

	assert(event_cb && read_cb && ptr->bev);
	bufferevent_setcb(ptr->bev, read_cb, NULL, event_cb, cb_ctx);

	return true;

error:
	return false;
}

static bool pgs_session_v2ray_outbound_init(
	pgs_session_outbound_t *ptr, const pgs_server_config_t *config,
	const uint8_t *cmd, uint64_t cmd_len, struct event_base *base,
	on_event_cb *event_cb, on_read_cb *read_cb, void *cb_ctx)
{
	pgs_v2rayserver_config_t *vconf =
		(pgs_v2rayserver_config_t *)config->extra;

	ptr->ctx = pgs_vmess_ctx_new(cmd, cmd_len, vconf->secure);

	if (vconf->ssl.enabled && vconf->ssl_ctx) {
		// ssl + vmess
		const char *sni = config->server_address;
		if (vconf->ssl.sni != NULL) {
			sni = vconf->ssl.sni;
		}
		if (pgs_session_outbound_ssl_bev_init(&ptr->bev, base,
						      vconf->ssl_ctx, sni))
			goto error;
	} else {
		// raw vmess
		ptr->bev = bufferevent_socket_new(
			base, -1,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	}

	assert(event_cb && read_cb && ptr->bev);
	bufferevent_setcb(ptr->bev, read_cb, NULL, event_cb, cb_ctx);
	return true;

error:
	return false;
}

static bool pgs_session_bypass_outbound_init(pgs_session_outbound_t *ptr,
					     struct event_base *base,
					     on_event_cb *event_cb,
					     on_read_cb *read_cb, void *cb_ctx)
{
	if (event_cb == NULL || read_cb == NULL)
		goto error;
	ptr->ctx = NULL;
	ptr->bev = bufferevent_socket_new(
		base, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	bufferevent_setcb(ptr->bev, read_cb, NULL, event_cb, cb_ctx);
	bufferevent_enable(ptr->bev, EV_READ);
	ptr->ready = true;
	ptr->bypass = true;

	return true;
error:
	return false;
}

static pgs_session_outbound_t *pgs_session_outbound_new()
{
	pgs_session_outbound_t *ptr = malloc(sizeof(pgs_session_outbound_t));
	ptr->ready = false;
	ptr->bypass = false;
	ptr->dest = NULL;
	ptr->port = 0;
	ptr->config = NULL;
	ptr->bev = NULL;
	ptr->ctx = NULL;

	return ptr;
}

static bool pgs_session_outbound_init(
	pgs_session_outbound_t *ptr, bool is_udp, const pgs_config_t *gconfig,
	const pgs_server_config_t *config, const uint8_t *cmd, uint64_t cmd_len,
	pgs_logger_t *logger, struct event_base *base,
	struct evdns_base *dns_base, pgs_acl_t *acl,
	pgs_session_outbound_cbs_t outbound_cbs, void *cb_ctx)
{
	ptr->config = config;

	bool proxy = true;
	// CHECK if all zeros for UDP
	socks5_dest_addr_parse(cmd, cmd_len, acl, &proxy, &ptr->dest,
			       &ptr->port);

	if (ptr->dest == NULL) {
		pgs_logger_error(logger, "socks5_dest_addr_parse");
		goto error;
	}

	if (proxy || is_udp) {
		if (IS_TROJAN_SERVER(config->server_type)) {
			if (!pgs_session_trojan_outbound_init(
				    ptr, config, cmd, cmd_len, base,
				    outbound_cbs.on_trojan_remote_event,
				    outbound_cbs.on_trojan_remote_read,
				    cb_ctx)) {
				pgs_logger_error(
					logger,
					"Failed to init trojan outbound");
				goto error;
			}
		} else if (IS_V2RAY_SERVER(config->server_type)) {
			if (!pgs_session_v2ray_outbound_init(
				    ptr, config, cmd, cmd_len, base,
				    outbound_cbs.on_v2ray_remote_event,
				    outbound_cbs.on_v2ray_remote_read,
				    cb_ctx)) {
				pgs_logger_error(
					logger,
					"Failed to init v2ray outbound");
				goto error;
			}
		}

		bufferevent_enable(ptr->bev, EV_READ);

		bufferevent_socket_connect_hostname(ptr->bev, dns_base, AF_INET,
						    config->server_address,
						    config->server_port);

		pgs_logger_debug(logger, "connect: %s:%d",
				 config->server_address, config->server_port);
	}
	if (!proxy || is_udp) {
		if (is_udp) {
			// do nothing
		} else {
			pgs_session_bypass_outbound_init(
				ptr, base, outbound_cbs.on_bypass_remote_event,
				outbound_cbs.on_bypass_remote_read, cb_ctx);

			pgs_logger_info(logger, "bypass: %s:%d", ptr->dest,
					ptr->port);
			bufferevent_socket_connect_hostname(ptr->bev, dns_base,
							    AF_INET, ptr->dest,
							    ptr->port);
		}
	}

	return true;

error:
	return false;
}

#endif
