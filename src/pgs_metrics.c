#include "pgs_metrics.h"

const unsigned char g204_cmd[] = { 0x05, 0x01, 0x00, 0x03, 0x0d, 0x77, 0x77,
				   0x77, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
				   0x65, 0x2e, 0x63, 0x6e, 0x00, 0x50 };

const char g204_http_req[] =
	"GET /generate_204 HTTP/1.1\r\nHost: www.google.cn\r\n\r\n";

static void do_ws_remote_request(pgs_bev_t *bev, void *ctx);
static void on_ws_g204_event(pgs_bev_t *bev, short events, void *ctx);
static void on_trojan_ws_g204_read(pgs_bev_t *bev, void *ctx);
static void on_v2ray_ws_g204_read(pgs_bev_t *bev, void *ctx);
static void on_trojan_gfw_g204_read(pgs_bev_t *bev, void *ctx);
static void on_trojan_gfw_g204_event(pgs_bev_t *bev, short events, void *ctx);
static void on_v2ray_tcp_g204_read(pgs_bev_t *bev, void *ctx);
static void on_v2ray_tcp_g204_event(pgs_bev_t *bev, short events, void *ctx);

void get_metrics_g204_connect(pgs_ev_base_t *base, pgs_server_manager_t *sm,
			      int idx, pgs_logger_t *logger)
{
	const pgs_server_config_t *config = &sm->server_configs[idx];
	pgs_session_outbound_t *ptr =
		pgs_malloc(sizeof(pgs_session_outbound_t));
	ptr->config = config;
	ptr->config_idx = idx;

	const pgs_buf_t *cmd = g204_cmd;
	pgs_size_t cmd_len = 20;

	ptr->port = (cmd[cmd_len - 2] << 8) | cmd[cmd_len - 1];
	ptr->dest = socks5_dest_addr_parse(cmd, cmd_len);

	ptr->bev = NULL;
	ptr->ctx = NULL;

	pgs_metrics_task_ctx_t *mctx =
		pgs_metrics_task_ctx_new(base, sm, idx, logger, ptr);

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
				      on_ws_g204_event, mctx);
			pgs_bev_enable(ptr->bev, EV_READ);
		} else {
			// trojan-gfw
			pgs_bev_setcb(ptr->bev, on_trojan_gfw_g204_read, NULL,
				      on_trojan_gfw_g204_event, mctx);
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
				      on_v2ray_tcp_g204_event, mctx);
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
				      on_ws_g204_event, mctx);
		}
		pgs_bev_enable(ptr->bev, EV_READ);
	}

	// do request
	mctx->start_at = clock();
	pgs_logger_debug(mctx->logger, "connect: %s:%d", config->server_address,
			 config->server_port);
	pgs_bev_socket_connect_hostname(mctx->outbound->bev, mctx->dns_base,
					AF_INET, config->server_address,
					config->server_port);
	return;
error:
	if (ptr)
		pgs_session_outbound_free(ptr);
	if (mctx)
		pgs_metrics_task_ctx_free(mctx);
}

static void on_ws_g204_event(pgs_bev_t *bev, short events, void *ctx)
{
	pgs_metrics_task_ctx_t *mctx = ctx;
	if (events & BEV_EVENT_CONNECTED)
		do_ws_remote_request(bev, ctx);
	if (events & BEV_EVENT_ERROR)
		pgs_logger_error(mctx->logger, "Error from bufferevent");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		pgs_ssl_t *ssl = pgs_bev_openssl_get_ssl(bev);
		if (ssl)
			pgs_ssl_close(ssl);
		pgs_bev_free(bev);
		if (mctx)
			pgs_metrics_task_ctx_free(mctx);
	}
}
static void on_trojan_ws_g204_read(pgs_bev_t *bev, void *ctx)
{
	// ws status
	// with data
}

static void v2ray_ws_vmess_write_cb(pgs_evbuffer_t *writer, pgs_buf_t *data,
				    pgs_size_t len)
{
	pgs_ws_write_bin(writer, data, len);
}

static void on_v2ray_ws_g204_read(pgs_bev_t *bev, void *ctx)
{
	pgs_metrics_task_ctx_t *mctx = ctx;
	pgs_logger_debug(mctx->logger, "remote read triggered");
	pgs_evbuffer_t *output = pgs_bev_get_output(bev);
	pgs_evbuffer_t *input = pgs_bev_get_input(bev);

	pgs_size_t data_len = pgs_evbuffer_get_length(input);
	unsigned char *data = pgs_evbuffer_pullup(input, data_len);
	pgs_logger_debug_buffer(mctx->logger, data, data_len);

	pgs_vmess_ctx_t *v2ray_s_ctx = mctx->outbound->ctx;
	if (!v2ray_s_ctx->connected) {
		if (!strstr((const char *)data, "\r\n\r\n"))
			return;

		if (pgs_ws_upgrade_check((const char *)data)) {
			pgs_logger_error(mctx->logger,
					 "websocket upgrade fail!");
			on_ws_g204_event(bev, BEV_EVENT_ERROR, ctx);
		} else {
			//drain
			pgs_evbuffer_drain(input, data_len);
			v2ray_s_ctx->connected = true;
			clock_t now = clock();
			double connect_time = now - mctx->start_at;
			connect_time /= (CLOCKS_PER_SEC / 1000);
			pgs_logger_debug(mctx->logger, "connect: %f",
					 connect_time);
			mctx->sm->server_stats[mctx->server_idx].connect_delay =
				connect_time;
			pgs_size_t total_len = pgs_vmess_write(
				(const pgs_buf_t *)
					mctx->outbound->config->password,
				(const pgs_buf_t *)g204_http_req,
				strlen(g204_http_req), v2ray_s_ctx, output,
				(pgs_vmess_write_body_cb)&v2ray_ws_vmess_write_cb);
		}
	} else {
		clock_t now = clock();
		double g204_time = now - mctx->start_at;
		g204_time /= (CLOCKS_PER_SEC / 1000);
		pgs_logger_debug(mctx->logger, "g204: %f", g204_time);
		mctx->sm->server_stats[mctx->server_idx].g204_delay = g204_time;
	}
}
static void on_trojan_gfw_g204_read(pgs_bev_t *bev, void *ctx)
{
	// with data
}
static void on_trojan_gfw_g204_event(pgs_bev_t *bev, short events, void *ctx)
{
	// connect time and error handling
}
static void on_v2ray_tcp_g204_read(pgs_bev_t *bev, void *ctx)
{
	// data
}
static void on_v2ray_tcp_g204_event(pgs_bev_t *bev, short events, void *ctx)
{
	// connect time and error handling
}

static void do_ws_remote_request(pgs_bev_t *bev, void *ctx)
{
	pgs_metrics_task_ctx_t *mctx = (pgs_metrics_task_ctx_t *)ctx;
	const pgs_server_config_t *config = mctx->outbound->config;
	// TODO: should assert here
	const pgs_server_ws_config_base_t *wsconfig = config->extra;

	pgs_logger_debug(mctx->logger, "do_ws_remote_request");

	pgs_ws_req(pgs_bev_get_output(mctx->outbound->bev),
		   wsconfig->websocket.hostname, config->server_address,
		   config->server_port, wsconfig->websocket.path);

	pgs_logger_debug(mctx->logger, "do_ws_remote_request done");
}

pgs_metrics_task_ctx_t *
pgs_metrics_task_ctx_new(pgs_ev_base_t *base, pgs_server_manager_t *sm, int idx,
			 pgs_logger_t *logger, pgs_session_outbound_t *outbound)
{
	pgs_metrics_task_ctx_t *ptr =
		pgs_malloc(sizeof(pgs_metrics_task_ctx_t));
	ptr->base = base;
	ptr->dns_base =
		pgs_ev_dns_base_new(base, EVDNS_BASE_INITIALIZE_NAMESERVERS);
	ptr->sm = sm;
	ptr->server_idx = idx;
	ptr->logger = logger;
	ptr->outbound = outbound;
	ptr->start_at = clock();
	return ptr;
}

void pgs_metrics_task_ctx_free(pgs_metrics_task_ctx_t *ptr)
{
	if (ptr) {
		if (ptr->outbound) {
			pgs_session_outbound_free(ptr->outbound);
			ptr->outbound = NULL;
		}
		if (ptr->dns_base) {
			pgs_ev_dns_base_free(ptr->dns_base, 0);
			ptr->dns_base = NULL;
		}
		pgs_free(ptr);
		ptr = NULL;
	}
}
