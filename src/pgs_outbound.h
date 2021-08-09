#ifndef _PGS_OUTBOUND
#define _PGS_OUTBOUND

#include "pgs_config.h"
#include "pgs_crypto.h"

#include <stdint.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>

typedef void(on_event_cb)(struct bufferevent *bev, short events, void *ctx);
typedef void(on_read_cb)(struct bufferevent *bev, void *ctx);

typedef struct pgs_session_outbound_cbs_s {
	on_event_cb *on_trojan_ws_remote_event;
	on_event_cb *on_trojan_gfw_remote_event;
	on_event_cb *on_v2ray_ws_remote_event;
	on_event_cb *on_v2ray_tcp_remote_event;
	on_read_cb *on_trojan_ws_remote_read;
	on_read_cb *on_trojan_gfw_remote_read;
	on_read_cb *on_v2ray_ws_remote_read;
	on_read_cb *on_v2ray_tcp_remote_read;
} pgs_session_outbound_cbs_t;

typedef struct pgs_session_outbound_s {
	struct bufferevent *bev;
	const pgs_server_config_t *config;
	int config_idx;
	char *dest;
	int port;
	void *ctx;
} pgs_session_outbound_t;

typedef struct pgs_trojansession_ctx_s {
	// sha224(password) + "\r\n" + cmd[1] + cmd.substr(3) + "\r\n"
	char *head;
	uint64_t head_len;
	bool connected;
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
	// for ws state
	bool connected;
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
	pgs_v2rayserver_secure_t secure;
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

static char *socks5_dest_addr_parse(const uint8_t *cmd, uint64_t cmd_len)
{
	int atyp = cmd[3];
	int offset = 4;
	char *dest = NULL;
	switch (atyp) {
	case 0x01: {
		assert(cmd_len > 8);
		dest = (char *)malloc(sizeof(char) * 32);
		sprintf(dest, "%d.%d.%d.%d", cmd[offset], cmd[offset + 1],
			cmd[offset + 2], cmd[offset + 3]);
		break;
	}
	case 0x03: {
		offset = 5;
		int len = cmd[4];
		assert(cmd_len > len + 4);
		dest = (char *)malloc(sizeof(char) * (len + 1));
		memcpy(dest, cmd + 5, len);
		dest[len] = '\0';
		break;
	}
	case 0x04: {
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
		break;
	}
	default:
		break;
	}
	return dest;
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

	ptr->connected = false;
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
					  pgs_v2rayserver_secure_t secure)
{
	pgs_vmess_ctx_t *ptr =
		(pgs_vmess_ctx_t *)malloc(sizeof(pgs_vmess_ctx_t));
	ptr->connected = false;

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
		if (ptr->secure == V2RAY_SECURE_CFB)
			pgs_aes_cryptor_free(
				(pgs_aes_cryptor_t *)ptr->encryptor);
		else
			pgs_aead_cryptor_free(
				(pgs_aead_cryptor_t *)ptr->encryptor);
	}
	if (ptr->decryptor) {
		if (ptr->secure == V2RAY_SECURE_CFB)
			pgs_aes_cryptor_free(
				(pgs_aes_cryptor_t *)ptr->decryptor);
		else
			pgs_aead_cryptor_free(
				(pgs_aead_cryptor_t *)ptr->decryptor);
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
		if (strcmp(ptr->config->server_type, "trojan") == 0) {
			pgs_trojansession_ctx_free(
				(pgs_trojansession_ctx_t *)ptr->ctx);
		}
		if (strcmp(ptr->config->server_type, "v2ray") == 0) {
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

static pgs_session_outbound_t *
pgs_session_outbound_new(const pgs_server_config_t *config, int config_idx,
			 const uint8_t *cmd, uint64_t cmd_len,
			 pgs_logger_t *logger, struct event_base *base,
			 struct evdns_base *dns_base,
			 pgs_session_outbound_cbs_t outbound_cbs, void *cb_ctx)
{
	pgs_session_outbound_t *ptr = (pgs_session_outbound_t *)malloc(
		sizeof(pgs_session_outbound_t));
	ptr->config = config;
	ptr->config_idx = config_idx;
	ptr->bev = NULL;
	ptr->ctx = NULL;

	// CHECK if all zeros for UDP
	ptr->port = (cmd[cmd_len - 2] << 8) | cmd[cmd_len - 1];
	ptr->dest = socks5_dest_addr_parse(cmd, cmd_len);

	if (ptr->dest == NULL) {
		pgs_logger_error(logger, "socks5_dest_addr_parse");
		goto error;
	}

	if (strcmp(config->server_type, "trojan") == 0) {
		pgs_trojanserver_config_t *trojanconf =
			(pgs_trojanserver_config_t *)config->extra;
		ptr->ctx = pgs_trojansession_ctx_new(config->password, 56, cmd,
						     cmd_len);
		// sni
		const char *sni = config->server_address;
		if (trojanconf->ssl.sni != NULL) {
			sni = trojanconf->ssl.sni;
		}
		SSL *ssl = pgs_ssl_new(trojanconf->ssl_ctx, (void *)sni);

		if (ssl == NULL) {
			pgs_logger_error(logger, "SSL_new");
			goto error;
		}
		ptr->bev = bufferevent_openssl_socket_new(
			base, -1, ssl, BUFFEREVENT_SSL_CONNECTING,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
		bufferevent_openssl_set_allow_dirty_shutdown(ptr->bev, 1);

		if (trojanconf->websocket.enabled) {
			// websocket support(trojan-go)
			assert(outbound_cbs.on_trojan_ws_remote_event &&
			       outbound_cbs.on_trojan_ws_remote_read);
			bufferevent_setcb(
				ptr->bev, outbound_cbs.on_trojan_ws_remote_read,
				NULL, outbound_cbs.on_trojan_ws_remote_event,
				cb_ctx);

			bufferevent_enable(ptr->bev, EV_READ);
		} else {
			// trojan-gfw
			assert(outbound_cbs.on_trojan_gfw_remote_event &&
			       outbound_cbs.on_trojan_gfw_remote_read);
			bufferevent_setcb(
				ptr->bev,
				outbound_cbs.on_trojan_gfw_remote_read, NULL,
				outbound_cbs.on_trojan_gfw_remote_event,
				cb_ctx);

			bufferevent_enable(ptr->bev, EV_READ);
		}
	} else if (strcmp(config->server_type, "v2ray") == 0) {
		pgs_v2rayserver_config_t *vconf =
			(pgs_v2rayserver_config_t *)config->extra;
		if (!vconf->websocket.enabled) {
			// raw tcp vmess
			ptr->ctx =
				pgs_vmess_ctx_new(cmd, cmd_len, vconf->secure);

			ptr->bev = bufferevent_socket_new(
				base, -1,
				BEV_OPT_CLOSE_ON_FREE |
					BEV_OPT_DEFER_CALLBACKS);

			assert(outbound_cbs.on_v2ray_tcp_remote_event &&
			       outbound_cbs.on_v2ray_tcp_remote_read);
			bufferevent_setcb(
				ptr->bev, outbound_cbs.on_v2ray_tcp_remote_read,
				NULL, outbound_cbs.on_v2ray_tcp_remote_event,
				cb_ctx);
		} else {
			// websocket can be protected by ssl
			if (vconf->ssl.enabled && vconf->ssl_ctx) {
				const char *sni = config->server_address;
				if (vconf->ssl.sni != NULL) {
					sni = vconf->ssl.sni;
				}
				SSL *ssl = pgs_ssl_new(vconf->ssl_ctx,
						       (void *)sni);
				if (ssl == NULL) {
					pgs_logger_error(logger, "SSL_new");
					goto error;
				}
				ptr->bev = bufferevent_openssl_socket_new(
					base, -1, ssl,
					BUFFEREVENT_SSL_CONNECTING,
					BEV_OPT_CLOSE_ON_FREE |
						BEV_OPT_DEFER_CALLBACKS);
				bufferevent_openssl_set_allow_dirty_shutdown(
					ptr->bev, 1);
			} else {
				ptr->bev = bufferevent_socket_new(
					base, -1,
					BEV_OPT_CLOSE_ON_FREE |
						BEV_OPT_DEFER_CALLBACKS);
			}
			ptr->ctx =
				pgs_vmess_ctx_new(cmd, cmd_len, vconf->secure);

			assert(outbound_cbs.on_v2ray_ws_remote_event &&
			       outbound_cbs.on_v2ray_ws_remote_read);
			bufferevent_setcb(ptr->bev,
					  outbound_cbs.on_v2ray_ws_remote_read,
					  NULL,
					  outbound_cbs.on_v2ray_ws_remote_event,
					  cb_ctx);
		}
		bufferevent_enable(ptr->bev, EV_READ);
	}

	// fire request
	pgs_logger_debug(logger, "connect: %s:%d", config->server_address,
			 config->server_port);

	bufferevent_socket_connect_hostname(ptr->bev, dns_base, AF_INET,
					    config->server_address,
					    config->server_port);

	return ptr;

error:
	pgs_session_outbound_free(ptr);
	return NULL;
}

#endif
