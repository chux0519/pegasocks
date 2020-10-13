#include "pgs_control.h"
#include <ctype.h>

#define zero_to_minus_one(n) (((n) == 0) ? (-1) : (n))

const char controller_herp_msg[] =
	"Support commands: PING | GET SERVERS | SET SERVER $idx\n";

static void accept_conn_cb(pgs_listener_t *listener, pgs_socket_t fd,
			   pgs_sockaddr_t *address, int socklen, void *ctx);
static void accept_error_cb(pgs_listener_t *listener, void *ctx);
static void on_control_read(pgs_bev_t *bev, void *ctx);
static void on_control_event(pgs_bev_t *bev, short events, void *ctx);

static bool starts_with(const char *pre, const char *str)
{
	size_t lenpre = strlen(pre), lenstr = strlen(str);
	if (lenstr < lenpre)
		return false;
	for (size_t i = 0; i < lenpre; i++) {
		if (tolower(pre[i]) != tolower(str[i]))
			return false;
	}
	return true;
}

void pgs_control_server_start(int fd, pgs_ev_base_t *base,
			      pgs_server_manager_t *sm, pgs_logger_t *logger,
			      const pgs_config_t *config)
{
	pgs_control_server_ctx_t *ptr = pgs_control_server_ctx_new();
	ptr->base = base;
	ptr->sm = sm;
	ptr->logger = logger;
	ptr->config = config;
	ptr->listener =
		pgs_listener_new(base, accept_conn_cb, ptr,
				 LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
				 fd);
	pgs_listener_set_error_cb(ptr->listener, accept_error_cb);
	if (config->control_port) {
		pgs_logger_info(logger, "Controller Listening at: %s:%d",
				config->local_address, config->control_port);
	} else if (config->control_file) {
		pgs_logger_info(logger, "Controller Listening at: %s",
				config->control_file);
	}
}

pgs_control_server_ctx_t *pgs_control_server_ctx_new()
{
	pgs_control_server_ctx_t *ptr =
		pgs_malloc(sizeof(pgs_control_server_ctx_t));
	return ptr;
}

void pgs_control_server_ctx_destroy(pgs_control_server_ctx_t *ptr)
{
	if (ptr) {
		pgs_free(ptr);
		ptr = NULL;
	}
}

static void accept_error_cb(pgs_listener_t *listener, void *ctx)
{
	pgs_control_server_ctx_t *control_ctx = (pgs_control_server_ctx_t *)ctx;

	int err = PGS_EVUTIL_SOCKET_ERROR();

	pgs_logger_debug(control_ctx->logger,
			 "Got an error %d (%s) on the control pannel listener."
			 "Shutting down \n",
			 err, pgs_evutil_socket_error_to_string(err));

	pgs_ev_base_loopexit(control_ctx->base, NULL);
	pgs_control_server_ctx_destroy(control_ctx);
}

static void accept_conn_cb(pgs_listener_t *listener, pgs_socket_t fd,
			   pgs_sockaddr_t *address, int socklen, void *ctx)
{
	pgs_control_server_ctx_t *control_ctx = (pgs_control_server_ctx_t *)ctx;
	struct sockaddr_in *sin = (struct sockaddr_in *)address;
	char *ip = inet_ntoa(sin->sin_addr);

	pgs_logger_debug(control_ctx->logger,
			 "new control client from port %s:%d", ip,
			 sin->sin_port);

	pgs_bev_t *bev = pgs_bev_socket_new(control_ctx->base, fd,
					    BEV_OPT_CLOSE_ON_FREE);
	pgs_bev_setcb(bev, on_control_read, NULL, on_control_event, ctx);
	pgs_bev_enable(bev, EV_READ);
}

static void on_control_read(pgs_bev_t *bev, void *ctx)
{
	pgs_control_server_ctx_t *control_ctx = (pgs_control_server_ctx_t *)ctx;
	// read and parse commands
	pgs_evbuffer_t *output = pgs_bev_get_output(bev);
	pgs_evbuffer_t *input = pgs_bev_get_input(bev);

	pgs_size_t len = pgs_evbuffer_get_length(input);
	unsigned char *rdata = pgs_evbuffer_pullup(input, len);

	// Support commands are
	// PING | GET SERVERS | SET SERVER $idx
	if (starts_with("PING", (const char *)rdata)) {
		pgs_evbuffer_add(output, "PONG\n", 5);
	} else if (starts_with("GET SERVERS", (const char *)rdata)) {
		pgs_server_config_t *servers = control_ctx->config->servers;
		pgs_server_stats_t *stats = control_ctx->sm->server_stats;
		int cur_server_index = control_ctx->sm->cur_server_index;
		pgs_evbuffer_add_printf(output, "\n");
		for (int i = 0; i < control_ctx->config->servers_count; i++) {
			if (cur_server_index == i)
				pgs_evbuffer_add_printf(output, "*");
			else
				pgs_evbuffer_add_printf(output, " ");
			pgs_evbuffer_add_printf(output, "%d: %s\n", i,
						servers[i].server_address);
			pgs_evbuffer_add_printf(
				output,
				"\t%-8s| connect:%*.0f ms | g204:%*.0f ms\n",
				servers[i].server_type, 6,
				zero_to_minus_one(stats[i].connect_delay), 6,
				zero_to_minus_one(stats[i].g204_delay));
		}
		pgs_evbuffer_add_printf(output, "\n");
	} else if (starts_with("SET SERVER", (const char *)rdata)) {
		int idx = atoi((const char *)&rdata[10]);
		if (idx < control_ctx->config->servers_count) {
			// Notice: no lock here
			// do not change with systray and control port at the same time
			pgs_logger_info(
				control_ctx->logger,
				"switched to server %s, index: %d",
				control_ctx->config->servers[idx].server_address,
				idx);
			control_ctx->sm->cur_server_index = idx;
			pgs_evbuffer_add_printf(output, "OK\n");
		}

	} else {
		pgs_evbuffer_add(output, controller_herp_msg,
				 strlen(controller_herp_msg));
	}

	pgs_evbuffer_drain(input, len);
}

static void on_control_event(pgs_bev_t *bev, short events, void *ctx)
{
	// free buffer event and related session
	pgs_control_server_ctx_t *control_ctx = (pgs_control_server_ctx_t *)ctx;
	if (events & BEV_EVENT_ERROR)
		pgs_logger_error(control_ctx->logger, "Error from bufferevent");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		pgs_bev_free(bev);
	}
}
