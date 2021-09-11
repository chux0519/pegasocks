#include "pgs_metrics.h"

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
	const pgs_trojanserver_config_t *tconfig = mctx->config->extra;
	if (tconfig->websocket.enabled) {
		on_ws_g204_event(bev, events, ctx);
	} else {
		on_trojan_gfw_g204_event(bev, events, ctx);
	}
}

static void on_trojan_g204_read(struct bufferevent *bev, void *ctx)
{
	pgs_metrics_task_ctx_t *mctx = ctx;
	const pgs_trojanserver_config_t *tconfig = mctx->config->extra;
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
	const pgs_v2rayserver_config_t *vconfig = mctx->config->extra;
	if (vconfig->websocket.enabled) {
		on_ws_g204_event(bev, events, ctx);
	} else {
		on_v2ray_tcp_g204_event(bev, events, ctx);
	}
}

static void on_v2ray_g204_read(struct bufferevent *bev, void *ctx)
{
	pgs_metrics_task_ctx_t *mctx = ctx;
	const pgs_v2rayserver_config_t *vconfig = mctx->config->extra;
	if (vconfig->websocket.enabled) {
		on_v2ray_ws_g204_read(bev, ctx);
	} else {
		on_v2ray_tcp_g204_read(bev, ctx);
	}
}

void get_metrics_g204_connect(struct event_base *base, pgs_server_manager_t *sm,
			      int idx, pgs_logger_t *logger)
{
	const pgs_server_config_t *config = &sm->server_configs[idx];
	const uint8_t *cmd = g204_cmd;
	uint64_t cmd_len = 20;
	pgs_metrics_task_ctx_t *mctx =
		pgs_metrics_task_ctx_new(base, config, sm, idx, logger, NULL);

	pgs_session_outbound_cbs_t outbound_cbs = { on_trojan_g204_event,
						    on_v2ray_g204_event,
						    on_trojan_g204_read,
						    on_v2ray_g204_read };

	pgs_session_outbound_t *ptr =
		pgs_session_outbound_new(config, idx, cmd, cmd_len, logger,
					 base, mctx->dns_base, outbound_cbs,
					 mctx);
	mctx->outbound = ptr;
}

static void on_ws_g204_event(struct bufferevent *bev, short events, void *ctx)
{
	pgs_metrics_task_ctx_t *mctx = ctx;
	if (events & BEV_EVENT_CONNECTED)
		do_ws_remote_request(bev, ctx);
	if (events & BEV_EVENT_ERROR)
		pgs_logger_error(mctx->logger, "Error from bufferevent");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		bufferevent_free(bev);
		if (mctx)
			pgs_metrics_task_ctx_free(mctx);
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

	pgs_trojansession_ctx_t *trojan_s_ctx = mctx->outbound->ctx;
	if (!trojan_s_ctx->connected) {
		if (!strstr((const char *)data, "\r\n\r\n"))
			return;

		if (pgs_ws_upgrade_check((const char *)data)) {
			pgs_logger_error(mctx->logger,
					 "websocket upgrade fail!");
			on_ws_g204_event(bev, BEV_EVENT_ERROR, ctx);
		} else {
			//drain
			evbuffer_drain(input, data_len);
			trojan_s_ctx->connected = true;
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
		mctx->sm->server_stats[mctx->server_idx].g204_delay = g204_time;
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
			evbuffer_drain(input, data_len);
			v2ray_s_ctx->connected = true;
			double connect_time = elapse(mctx->start_at);
			pgs_logger_debug(mctx->logger, "connect: %f",
					 connect_time);
			mctx->sm->server_stats[mctx->server_idx].connect_delay =
				connect_time;
			pgs_session_t dummy = { 0 };
			dummy.outbound = mctx->outbound;
			uint64_t total_len = pgs_vmess_write_remote(
				&dummy, (const uint8_t *)g204_http_req,
				strlen(g204_http_req),
				(pgs_session_write_fn)&vmess_flush_remote);
		}
	} else {
		double g204_time = elapse(mctx->start_at);
		pgs_logger_debug(mctx->logger, "g204: %f", g204_time);
		mctx->sm->server_stats[mctx->server_idx].g204_delay = g204_time;
	}
}
static void on_trojan_gfw_g204_read(struct bufferevent *bev, void *ctx)
{
	// with data
	pgs_metrics_task_ctx_t *mctx = ctx;
	double g204_time = elapse(mctx->start_at);
	pgs_logger_debug(mctx->logger, "g204: %f", g204_time);
	mctx->sm->server_stats[mctx->server_idx].g204_delay = g204_time;
	on_trojan_gfw_g204_event(bev, BEV_EVENT_EOF, ctx);
}
static void on_trojan_gfw_g204_event(struct bufferevent *bev, short events,
				     void *ctx)
{
	// connect time and error handling
	pgs_metrics_task_ctx_t *mctx = ctx;
	if (events & BEV_EVENT_CONNECTED) {
		// set connected
		pgs_trojansession_ctx_t *sctx = mctx->outbound->ctx;
		sctx->connected = true;
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
			pgs_metrics_task_ctx_free(mctx);
	}
}
static void on_v2ray_tcp_g204_read(struct bufferevent *bev, void *ctx)
{
	pgs_metrics_task_ctx_t *mctx = ctx;
	double g204_time = elapse(mctx->start_at);
	pgs_logger_debug(mctx->logger, "g204: %f", g204_time);
	mctx->sm->server_stats[mctx->server_idx].g204_delay = g204_time;
	// drop it, clean up
	on_v2ray_tcp_g204_event(bev, BEV_EVENT_EOF, ctx);
}

// used for tcp/ssl
static void on_v2ray_tcp_g204_event(struct bufferevent *bev, short events,
				    void *ctx)
{
	pgs_metrics_task_ctx_t *mctx = ctx;
	if (events & BEV_EVENT_CONNECTED) {
		// set connected
		pgs_vmess_ctx_t *sctx = mctx->outbound->ctx;
		sctx->connected = true;
		double connect_time = elapse(mctx->start_at);
		pgs_logger_debug(mctx->logger, "connect: %f", connect_time);
		mctx->sm->server_stats[mctx->server_idx].connect_delay =
			connect_time;

		// write request
		pgs_session_t dummy = { 0 };
		dummy.outbound = mctx->outbound;
		struct evbuffer *output = bufferevent_get_output(bev);
		uint64_t total_len = pgs_vmess_write_remote(
			&dummy, (const uint8_t *)g204_http_req,
			strlen(g204_http_req),
			(pgs_session_write_fn)&vmess_flush_remote);
	}
	if (events & BEV_EVENT_ERROR)
		pgs_logger_error(mctx->logger, "Error from bufferevent");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		bufferevent_free(bev);
		if (mctx)
			pgs_metrics_task_ctx_free(mctx);
	}
}

static void do_ws_remote_request(struct bufferevent *bev, void *ctx)
{
	pgs_metrics_task_ctx_t *mctx = (pgs_metrics_task_ctx_t *)ctx;
	const pgs_server_config_t *config = mctx->outbound->config;
	// TODO: should assert here
	const pgs_server_ws_config_base_t *wsconfig = config->extra;

	pgs_logger_debug(mctx->logger, "do_ws_remote_request");

	pgs_ws_req(bufferevent_get_output(mctx->outbound->bev),
		   wsconfig->websocket.hostname, config->server_address,
		   config->server_port, wsconfig->websocket.path);

	pgs_logger_debug(mctx->logger, "do_ws_remote_request done");
}

pgs_metrics_task_ctx_t *
pgs_metrics_task_ctx_new(struct event_base *base,
			 const pgs_server_config_t *config,
			 pgs_server_manager_t *sm, int idx,
			 pgs_logger_t *logger, pgs_session_outbound_t *outbound)
{
	pgs_metrics_task_ctx_t *ptr = malloc(sizeof(pgs_metrics_task_ctx_t));
	ptr->base = base;
	ptr->dns_base = evdns_base_new(base, EVDNS_BASE_INITIALIZE_NAMESERVERS);
	ptr->config = config;
	ptr->sm = sm;
	ptr->server_idx = idx;
	ptr->logger = logger;
	ptr->outbound = outbound;
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
