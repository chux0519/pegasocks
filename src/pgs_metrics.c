#include "pgs_metrics.h"

const unsigned char g204_cmd[21] = { 0x05, 0x01, 0x00, 0x03, 0x0e, 0x77, 0x77,
				     0x77, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
				     0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x50 };

static void on_trojan_ws_connect_read(pgs_bev_t *bev, void *ctx);
static void on_trojan_ws_connect_event(pgs_bev_t *bev, short events, void *ctx);
static void on_trojan_gfw_connect_read(pgs_bev_t *bev, void *ctx);
static void on_trojan_gfw_connect_event(pgs_bev_t *bev, short events,
					void *ctx);
static void on_v2ray_tcp_connect_read(pgs_bev_t *bev, void *ctx);
static void on_v2ray_tcp_connect_event(pgs_bev_t *bev, short events, void *ctx);
static void on_v2ray_ws_connect_read(pgs_bev_t *bev, void *ctx);
static void on_v2ray_ws_connect_event(pgs_bev_t *bev, short events, void *ctx);

// TODO:
static void on_trojan_ws_g204_read(pgs_bev_t *bev, void *ctx);
static void on_trojan_ws_g204_event(pgs_bev_t *bev, short events, void *ctx);
static void on_trojan_gfw_g204_read(pgs_bev_t *bev, void *ctx);
static void on_trojan_gfw_g204_event(pgs_bev_t *bev, short events, void *ctx);
static void on_v2ray_tcp_g204_read(pgs_bev_t *bev, void *ctx);
static void on_v2ray_tcp_g204_event(pgs_bev_t *bev, short events, void *ctx);
static void on_v2ray_ws_g204_read(pgs_bev_t *bev, void *ctx);
static void on_v2ray_ws_g204_event(pgs_bev_t *bev, short events, void *ctx);

void get_metrics_connect(pgs_ev_base_t *base, pgs_server_manager_t *sm, int idx)
{
}

// TODO: add logger as param and add it to context
void get_metrics_g204(pgs_ev_base_t *base, pgs_server_manager_t *sm, int idx)
{
	// new ev based on types
	const pgs_server_config_t *config = &sm->server_configs[idx];
	pgs_session_outbound_t *ptr =
		pgs_malloc(sizeof(pgs_session_outbound_t));
	ptr->config = config;
	ptr->config_idx = idx;

	const pgs_buf_t *cmd = g204_cmd;
	pgs_size_t cmd_len = 21;

	ptr->port = (cmd[cmd_len - 2] << 8) | cmd[cmd_len - 1];
	ptr->dest = socks5_dest_addr_parse(cmd, cmd_len);

	ptr->bev = NULL;
	ptr->ctx = NULL;

	if (strcmp(config->server_type, "trojan") == 0) {
		pgs_trojanserver_config_t *trojanconf = config->extra;
		ptr->ctx = pgs_trojansession_ctx_new(config->password, 56, cmd,
						     cmd_len);

		pgs_ssl_t *ssl = pgs_ssl_new(trojanconf->ssl_ctx,
					     (void *)config->server_address);
		if (ssl == NULL) {
			goto error;
		}
		ptr->bev = pgs_bev_openssl_socket_new(
			base, -1, ssl, BUFFEREVENT_SSL_CONNECTING,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
		pgs_bev_openssl_set_allow_dirty_shutdown(ptr->bev, 1);

		if (trojanconf->websocket.enabled) {
			// websocket support(trojan-go)
			pgs_bev_setcb(ptr->bev, on_trojan_ws_g204_read, NULL,
				      on_trojan_ws_g204_event, NULL);
			pgs_bev_enable(ptr->bev, EV_READ);
		} else {
			// trojan-gfw
			pgs_bev_setcb(ptr->bev, on_trojan_gfw_g204_read, NULL,
				      on_trojan_gfw_g204_event, NULL);
			pgs_bev_enable(ptr->bev, EV_READ);
		}
	} else if (strcmp(config->server_type, "v2ray") == 0) {
		pgs_v2rayserver_config_t *vconf = config->extra;
		if (!vconf->websocket.enabled) {
			// raw tcp vmess
			ptr->ctx =
				pgs_vmess_ctx_new(cmd, cmd_len, vconf->secure);

			ptr->bev = bufferevent_socket_new(
				base, -1,
				BEV_OPT_CLOSE_ON_FREE |
					BEV_OPT_DEFER_CALLBACKS);

			pgs_bev_setcb(ptr->bev, on_v2ray_tcp_g204_read, NULL,
				      on_v2ray_tcp_g204_event, NULL);
		} else {
			// websocket can be protected by ssl
			if (vconf->ssl.enabled && vconf->ssl_ctx) {
				pgs_ssl_t *ssl = pgs_ssl_new(
					vconf->ssl_ctx,
					(void *)config->server_address);
				if (ssl == NULL) {
					goto error;
				}
				ptr->bev = pgs_bev_openssl_socket_new(
					base, -1, ssl,
					BUFFEREVENT_SSL_CONNECTING,
					BEV_OPT_CLOSE_ON_FREE |
						BEV_OPT_DEFER_CALLBACKS);
				pgs_bev_openssl_set_allow_dirty_shutdown(
					ptr->bev, 1);
			} else {
				ptr->bev = bufferevent_socket_new(
					base, -1,
					BEV_OPT_CLOSE_ON_FREE |
						BEV_OPT_DEFER_CALLBACKS);
			}
			ptr->ctx =
				pgs_vmess_ctx_new(cmd, cmd_len, vconf->secure);

			pgs_bev_setcb(ptr->bev, on_v2ray_ws_g204_read, NULL,
				      on_v2ray_ws_g204_event, NULL);
		}
		pgs_bev_enable(ptr->bev, EV_READ);
	}
error:
	pgs_session_outbound_free(ptr);
}

static void on_trojan_ws_g204_read(pgs_bev_t *bev, void *ctx)
{
}
static void on_trojan_ws_g204_event(pgs_bev_t *bev, short events, void *ctx)
{
}
static void on_trojan_gfw_g204_read(pgs_bev_t *bev, void *ctx)
{
}
static void on_trojan_gfw_g204_event(pgs_bev_t *bev, short events, void *ctx)
{
}
static void on_v2ray_tcp_g204_read(pgs_bev_t *bev, void *ctx)
{
}
static void on_v2ray_tcp_g204_event(pgs_bev_t *bev, short events, void *ctx)
{
}
static void on_v2ray_ws_g204_read(pgs_bev_t *bev, void *ctx)
{
}
static void on_v2ray_ws_g204_event(pgs_bev_t *bev, short events, void *ctx)
{
}
