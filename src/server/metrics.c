#include "server/metrics.h"

#include "server/manager.h"
#include <event2/buffer.h>

#ifdef WITH_APPLET
#include "applet.h"
#endif

const unsigned char g204_cmd[] = { 0x05, 0x01, 0x00, 0x03, 0x0d, 0x77, 0x77,
				   0x77, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
				   0x65, 0x2e, 0x63, 0x6e, 0x00, 0x50 };

const char g204_http_req[] =
	"GET /generate_204 HTTP/1.1\r\nHost: www.google.cn\r\n\r\n";

static void do_ws_remote_request(struct bufferevent *bev, void *ctx);
static void on_ws_g204_event(struct bufferevent *bev, short events, void *ctx);
static void on_trojan_ws_g204_read(struct bufferevent *bev, void *ctx);
static void on_v2ray_ws_g204_read(struct bufferevent *bev, void *ctx);
static void on_trojan_gfw_g204_read(struct bufferevent *bev, void *ctx);
static void on_trojan_gfw_g204_event(struct bufferevent *bev, short events,
				     void *ctx);
static void on_v2ray_tcp_g204_read(struct bufferevent *bev, void *ctx);
static void on_v2ray_tcp_g204_event(struct bufferevent *bev, short events,
				    void *ctx);

static void on_ss_g204_read(struct bufferevent *bev, void *ctx);
static void on_ss_g204_event(struct bufferevent *bev, short events, void *ctx);

static void pgs_metrics_update(pgs_server_stats_t *stats, double g204_time)
{
	stats->g204_delay = g204_time;
#ifdef WITH_APPLET
	pgs_tray_update();
#endif
}

static double elapse(struct timeval start_at)
{
	struct timeval now;
	gettimeofday(&now, NULL);
	long seconds = now.tv_sec - start_at.tv_sec;
	long micros = ((seconds * 1000000) + now.tv_usec - start_at.tv_usec);
	return micros / 1000;
}

static void on_trojan_g204_event(struct bufferevent *bev, short events,
				 void *ctx)
{
	pgs_metrics_task_ctx_t *mctx = ctx;
	if (events & BEV_EVENT_TIMEOUT) {
		pgs_logger_error(mctx->logger, "(%s)%s:%d g204 timeout",
				 mctx->config->server_type,
				 mctx->config->server_address,
				 mctx->config->server_port);
		bufferevent_free(bev);
		if (mctx)
			PGS_FREE_METRICS_TASK(mctx);
		return;
	}
	const pgs_config_extra_trojan_t *tconfig = mctx->config->extra;
	if (tconfig->websocket.enabled) {
		on_ws_g204_event(bev, events, ctx);
	} else {
		on_trojan_gfw_g204_event(bev, events, ctx);
	}
}

static void on_trojan_g204_read(struct bufferevent *bev, void *ctx)
{
	pgs_metrics_task_ctx_t *mctx = ctx;
	const pgs_config_extra_trojan_t *tconfig = mctx->config->extra;
	if (tconfig->websocket.enabled) {
		on_trojan_ws_g204_read(bev, ctx);
	} else {
		on_trojan_gfw_g204_read(bev, ctx);
	}
}

static void on_v2ray_g204_event(struct bufferevent *bev, short events,
				void *ctx)
{
	pgs_metrics_task_ctx_t *mctx = ctx;
	if (events & BEV_EVENT_TIMEOUT) {
		pgs_logger_error(mctx->logger, "v2ray g204 timeout");
		bufferevent_free(bev);
		if (mctx)
			PGS_FREE_METRICS_TASK(mctx);
		return;
	}
	const pgs_config_extra_v2ray_t *vconfig = mctx->config->extra;
	if (vconfig->websocket.enabled) {
		on_ws_g204_event(bev, events, ctx);
	} else {
		on_v2ray_tcp_g204_event(bev, events, ctx);
	}
}

static void on_v2ray_g204_read(struct bufferevent *bev, void *ctx)
{
	pgs_metrics_task_ctx_t *mctx = ctx;
	const pgs_config_extra_v2ray_t *vconfig = mctx->config->extra;
	if (vconfig->websocket.enabled) {
		on_v2ray_ws_g204_read(bev, ctx);
	} else {
		on_v2ray_tcp_g204_read(bev, ctx);
	}
}

pgs_metrics_task_ctx_t *
get_metrics_g204_connect(int idx, struct event_base *base,
			 pgs_server_manager_t *sm, pgs_logger_t *logger,
			 pgs_ssl_ctx_t *ssl_ctx, pgs_list_t *mtasks)
{
	const pgs_server_config_t *config = &sm->server_configs[idx];
	const uint8_t *cmd = g204_cmd;
	uint64_t cmd_len = 20;
	pgs_metrics_task_ctx_t *mctx = pgs_metrics_task_ctx_new(
		idx, base, config, sm, logger, NULL, mtasks);

	pgs_session_outbound_t *ptr = pgs_session_outbound_new();
	mctx->outbound = ptr;
	ptr->config = config;

	bool proxy = true;
	socks5_dest_addr_parse(cmd, cmd_len, NULL, &proxy, &ptr->dest,
			       &ptr->port);
	if (ptr->dest == NULL) {
		pgs_logger_error(logger, "socks5_dest_addr_parse");
		goto error;
	}

	if (IS_TROJAN_SERVER(config->server_type)) {
		if (!pgs_session_trojan_outbound_init(
			    ptr, config, cmd, cmd_len, base, ssl_ctx,
			    on_trojan_g204_event, on_trojan_g204_read, mctx)) {
			pgs_logger_error(logger,
					 "Failed to init trojan outbound");
			goto error;
		}
	} else if (IS_V2RAY_SERVER(config->server_type)) {
		if (!pgs_session_v2ray_outbound_init(
			    ptr, config, cmd, cmd_len, base, ssl_ctx,
			    on_v2ray_g204_event, on_v2ray_g204_read, mctx)) {
			pgs_logger_error(logger,
					 "Failed to init v2ray outbound");
			goto error;
		}
	} else if (IS_SHADOWSOCKS_SERVER(config->server_type)) {
		if (!pgs_session_ss_outbound_init(ptr, config, cmd, cmd_len,
						  base, on_ss_g204_event,
						  on_ss_g204_read, mctx)) {
			pgs_logger_error(logger,
					 "Failed to init shadowsocks outbound");
			goto error;
		}
	} else {
		pgs_logger_error(logger, "Not supported server type: %s",
				 config->server_type);
		goto error;
	}

	bufferevent_enable(ptr->bev, EV_READ);
	PGS_OUTBOUND_SET_READ_TIMEOUT(ptr, 10);

	bufferevent_socket_connect_hostname(ptr->bev, mctx->dns_base, AF_INET,
					    config->server_address,
					    config->server_port);

	pgs_logger_debug(logger, "connect: %s:%d", config->server_address,
			 config->server_port);

	return mctx;

error:
	if (mctx)
		PGS_FREE_METRICS_TASK(mctx);
	return NULL;
}

static void on_ws_g204_event(struct bufferevent *bev, short events, void *ctx)
{
	pgs_metrics_task_ctx_t *mctx = ctx;
	if (events & BEV_EVENT_CONNECTED)
		do_ws_remote_request(bev, ctx);
	if (events & BEV_EVENT_ERROR)
		pgs_logger_error(mctx->logger, "ws g204 error");
	if (events & BEV_EVENT_TIMEOUT)
		pgs_logger_error(mctx->logger, "ws g204 timeout");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
		bufferevent_free(bev);
		if (mctx)
			PGS_FREE_METRICS_TASK(mctx);
	}
}

static void on_trojan_ws_g204_read(struct bufferevent *bev, void *ctx)
{
	pgs_metrics_task_ctx_t *mctx = ctx;
	pgs_logger_debug(mctx->logger, "remote read triggered");
	struct evbuffer *output = bufferevent_get_output(bev);
	struct evbuffer *input = bufferevent_get_input(bev);

	uint64_t data_len = evbuffer_get_length(input);
	unsigned char *data = evbuffer_pullup(input, data_len);

	pgs_outbound_ctx_trojan_t *trojan_s_ctx = mctx->outbound->ctx;
	if (!mctx->outbound->ready) {
		if (!strstr((const char *)data, "\r\n\r\n"))
			return;

		if (pgs_ws_upgrade_check((const char *)data)) {
			pgs_logger_error(mctx->logger,
					 "websocket upgrade fail!");
			on_ws_g204_event(bev, BEV_EVENT_ERROR, ctx);
		} else {
			//drain
			evbuffer_drain(input, data_len);
			mctx->outbound->ready = true;
			double connect_time = elapse(mctx->start_at);
			pgs_logger_debug(mctx->logger, "connect: %f",
					 connect_time);
			mctx->sm->server_stats[mctx->server_idx].connect_delay =
				connect_time;

			uint64_t len = strlen(g204_http_req);
			uint64_t head_len = trojan_s_ctx->head_len;

			if (head_len > 0)
				len += head_len;

			pgs_ws_write_head_text(output, len);

			if (head_len > 0) {
				evbuffer_add(output, trojan_s_ctx->head,
					     head_len);
				trojan_s_ctx->head_len = 0;
			}
			// x ^ 0 = x
			evbuffer_add(output, g204_http_req, len - head_len);
		}
	} else {
		double g204_time = elapse(mctx->start_at);
		pgs_logger_debug(mctx->logger, "g204: %f", g204_time);
		pgs_metrics_update(&mctx->sm->server_stats[mctx->server_idx],
				   g204_time);
	}
}

static void v2ray_ws_vmess_write_cb(struct evbuffer *writer, uint8_t *data,
				    uint64_t len)
{
	pgs_ws_write_bin(writer, data, len);
}

static void on_v2ray_ws_g204_read(struct bufferevent *bev, void *ctx)
{
	pgs_metrics_task_ctx_t *mctx = ctx;
	struct evbuffer *output = bufferevent_get_output(bev);
	struct evbuffer *input = bufferevent_get_input(bev);

	uint64_t data_len = evbuffer_get_length(input);
	unsigned char *data = evbuffer_pullup(input, data_len);

	pgs_outbound_ctx_v2ray_t *v2ray_s_ctx = mctx->outbound->ctx;
	if (!mctx->outbound->ready) {
		if (!strstr((const char *)data, "\r\n\r\n"))
			return;

		if (pgs_ws_upgrade_check((const char *)data)) {
			pgs_logger_error(mctx->logger,
					 "websocket upgrade fail!");
			on_ws_g204_event(bev, BEV_EVENT_ERROR, ctx);
		} else {
			//drain
			evbuffer_drain(input, data_len);
			mctx->outbound->ready = true;
			double connect_time = elapse(mctx->start_at);
			pgs_logger_debug(mctx->logger, "connect: %f",
					 connect_time);
			mctx->sm->server_stats[mctx->server_idx].connect_delay =
				connect_time;
			pgs_session_t dummy = { 0 };
			dummy.outbound = mctx->outbound;
			size_t olen = 0;
			bool ok = vmess_write_remote(
				&dummy, (const uint8_t *)g204_http_req,
				strlen(g204_http_req), &olen);
		}
	} else {
		double g204_time = elapse(mctx->start_at);
		pgs_logger_debug(mctx->logger, "g204: %f", g204_time);
		pgs_metrics_update(&mctx->sm->server_stats[mctx->server_idx],
				   g204_time);
		// drop it, clean up
		on_ws_g204_event(bev, BEV_EVENT_EOF, ctx);
	}
}
static void on_trojan_gfw_g204_read(struct bufferevent *bev, void *ctx)
{
	// with data
	pgs_metrics_task_ctx_t *mctx = ctx;
	double g204_time = elapse(mctx->start_at);
	pgs_logger_debug(mctx->logger, "g204: %f", g204_time);
	pgs_metrics_update(&mctx->sm->server_stats[mctx->server_idx],
			   g204_time);
	on_trojan_gfw_g204_event(bev, BEV_EVENT_EOF, ctx);
}
static void on_trojan_gfw_g204_event(struct bufferevent *bev, short events,
				     void *ctx)
{
	// connect time and error handling
	pgs_metrics_task_ctx_t *mctx = ctx;
	if (events & BEV_EVENT_CONNECTED) {
		// set connected
		pgs_outbound_ctx_trojan_t *sctx = mctx->outbound->ctx;
		mctx->outbound->ready = true;
		double connect_time = elapse(mctx->start_at);
		pgs_logger_debug(mctx->logger, "trojan gfw connected: %f",
				 connect_time);
		mctx->sm->server_stats[mctx->server_idx].connect_delay =
			connect_time;
		// write request
		struct evbuffer *output = bufferevent_get_output(bev);
		uint64_t len = strlen(g204_http_req);
		uint64_t head_len = sctx->head_len;
		if (head_len > 0)
			len += head_len;

		if (head_len > 0) {
			evbuffer_add(output, sctx->head, head_len);
			sctx->head_len = 0;
		}
		evbuffer_add(output, g204_http_req, len - head_len);
	}
	if (events & BEV_EVENT_ERROR)
		pgs_logger_error(mctx->logger, "Error from bufferevent");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		bufferevent_free(bev);
		if (mctx)
			PGS_FREE_METRICS_TASK(mctx);
	}
}
static void on_v2ray_tcp_g204_read(struct bufferevent *bev, void *ctx)
{
	pgs_metrics_task_ctx_t *mctx = ctx;
	double g204_time = elapse(mctx->start_at);
	pgs_logger_debug(mctx->logger, "g204: %f", g204_time);
	pgs_metrics_update(&mctx->sm->server_stats[mctx->server_idx],
			   g204_time);
	// drop it, clean up
	on_v2ray_tcp_g204_event(bev, BEV_EVENT_EOF, ctx);
}

static void on_ss_g204_read(struct bufferevent *bev, void *ctx)
{
	pgs_metrics_task_ctx_t *mctx = ctx;
	double g204_time = elapse(mctx->start_at);
	pgs_logger_debug(mctx->logger, "g204: %f", g204_time);
	pgs_metrics_update(&mctx->sm->server_stats[mctx->server_idx],
			   g204_time);
	// drop it, clean up
	on_ss_g204_event(bev, BEV_EVENT_EOF, ctx);
}

static void on_ss_g204_event(struct bufferevent *bev, short events, void *ctx)
{
	pgs_metrics_task_ctx_t *mctx = ctx;
	if (events & BEV_EVENT_TIMEOUT) {
		pgs_logger_error(mctx->logger, "shadowsocks g204 timeout");
		bufferevent_free(bev);
		if (mctx)
			PGS_FREE_METRICS_TASK(mctx);
		return;
	}
	if (events & BEV_EVENT_CONNECTED) {
		// set connected
		mctx->outbound->ready = true;
		double connect_time = elapse(mctx->start_at);
		pgs_logger_debug(mctx->logger, "connect: %f", connect_time);
		mctx->sm->server_stats[mctx->server_idx].connect_delay =
			connect_time;

		// write request
		pgs_session_t dummy = { 0 };
		dummy.outbound = mctx->outbound;
		struct evbuffer *output = bufferevent_get_output(bev);
		size_t olen = 0;
		bool ok =
			shadowsocks_write_remote(&dummy,
						 (const uint8_t *)g204_http_req,
						 strlen(g204_http_req), &olen);
		pgs_logger_debug(mctx->logger, "g204 req sent: %d", olen);
	}
	if (events & BEV_EVENT_ERROR)
		pgs_logger_error(mctx->logger, "Error from bufferevent");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		bufferevent_free(bev);
		if (mctx)
			PGS_FREE_METRICS_TASK(mctx);
	}
}

// used for tcp/ssl
static void on_v2ray_tcp_g204_event(struct bufferevent *bev, short events,
				    void *ctx)
{
	pgs_metrics_task_ctx_t *mctx = ctx;
	if (events & BEV_EVENT_CONNECTED) {
		// set connected
		pgs_outbound_ctx_v2ray_t *sctx = mctx->outbound->ctx;
		mctx->outbound->ready = true;
		double connect_time = elapse(mctx->start_at);
		pgs_logger_debug(mctx->logger, "connect: %f", connect_time);
		mctx->sm->server_stats[mctx->server_idx].connect_delay =
			connect_time;

		// write request
		pgs_session_t dummy = { 0 };
		dummy.outbound = mctx->outbound;
		struct evbuffer *output = bufferevent_get_output(bev);
		size_t olen = 0;
		bool ok = vmess_write_remote(&dummy,
					     (const uint8_t *)g204_http_req,
					     strlen(g204_http_req), &olen);
		pgs_logger_debug(mctx->logger, "g204 req sent: %d", olen);
	}
	if (events & BEV_EVENT_ERROR)
		pgs_logger_error(mctx->logger, "Error from bufferevent");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		bufferevent_free(bev);
		if (mctx)
			PGS_FREE_METRICS_TASK(mctx);
	}
}

static void do_ws_remote_request(struct bufferevent *bev, void *ctx)
{
	pgs_metrics_task_ctx_t *mctx = (pgs_metrics_task_ctx_t *)ctx;
	const pgs_server_config_t *config = mctx->outbound->config;

	const pgs_config_ws_t *ws_config = config->extra;

	pgs_logger_debug(mctx->logger, "do_ws_remote_request");

	pgs_ws_req(bufferevent_get_output(mctx->outbound->bev),
		   ws_config->hostname, config->server_address,
		   config->server_port, ws_config->path);

	pgs_logger_debug(mctx->logger, "do_ws_remote_request done");
}

pgs_metrics_task_ctx_t *
pgs_metrics_task_ctx_new(int idx, struct event_base *base,
			 const pgs_server_config_t *config,
			 pgs_server_manager_t *sm, pgs_logger_t *logger,
			 pgs_session_outbound_t *outbound, pgs_list_t *tasks)
{
	pgs_metrics_task_ctx_t *ptr = malloc(sizeof(pgs_metrics_task_ctx_t));
	ptr->base = base;
	ptr->dns_base = evdns_base_new(base, EVDNS_BASE_INITIALIZE_NAMESERVERS);
	ptr->config = config;
	ptr->sm = sm;
	ptr->server_idx = idx;
	ptr->logger = logger;
	ptr->outbound = outbound;

	ptr->node = pgs_list_node_new(ptr);
	ptr->mtasks = tasks;
	gettimeofday(&ptr->start_at, NULL);
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
			evdns_base_free(ptr->dns_base, 0);
			ptr->dns_base = NULL;
		}
		free(ptr);
		ptr = NULL;
	}
}
