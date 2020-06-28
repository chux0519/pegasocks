#include "pgs_server_manager.h"
#include "pgs_core.h"
#include <assert.h>

pgs_server_manager_t *
pgs_server_manager_new(pgs_mpsc_t *mpsc, pgs_server_config_t *server_configs,
		       int server_len)
{
	pgs_server_manager_t *ptr = pgs_malloc(sizeof(pgs_server_manager_t));
	ptr->mpsc = mpsc;
	ptr->server_stats = pgs_calloc(server_len, sizeof(pgs_server_stats_t));
	pgs_server_stats_init(ptr->server_stats, server_len);
	ptr->server_configs = server_configs;
	ptr->server_len = server_len;
	ptr->cur_server_index = 0;
	return ptr;
}

void pgs_server_manager_free(pgs_server_manager_t *ptr)
{
	pgs_free(ptr->server_stats);
	pgs_free(ptr);
}

void pgs_server_manager_tryrecv(pgs_server_manager_t *ptr)
{
	pgs_session_stats_msg_t *msg = pgs_mpsc_recv(ptr->mpsc);
	if (msg && msg->server_config_index >= ptr->server_len) {
		pgs_server_stats_t *stats =
			&ptr->server_stats[msg->server_config_index];
		int idx = stats->session_stats_index % ptr->server_len;
		pgs_server_session_stats_t *session_stats =
			&stats->session_stats[idx];
		session_stats->end = msg->data->end;
		session_stats->start = msg->data->start;
		session_stats->recv = msg->data->recv;
		session_stats->start = msg->data->end;
		stats->session_stats_index += 1;
	}
	if (msg) {
		pgs_free(msg->data);
		pgs_free(msg);
	}
}

/*
 * Get server config for session
 * not thread safe
 */
pgs_server_config_t *pgs_server_manager_get_config(pgs_server_manager_t *sm)
{
	assert(sm->cur_server_index < sm->server_len);
	return &sm->server_configs[sm->cur_server_index];
}

void pgs_server_stats_init(pgs_server_stats_t *ptr, int len)
{
	for (int i = 0; i < len; i++) {
		ptr[i].connect_delay = 0;
		ptr[i].g204_delay = 0;
		ptr[i].session_stats =
			pgs_malloc(MAX_SESSION_STATS_SIZE *
				   sizeof(pgs_server_session_stats_t));
		ptr[i].session_stats_index = 0;
	}
}

void pgs_server_stats_free(pgs_server_stats_t *ptr, int len)
{
	for (int i = 0; i < len; i++) {
		if (ptr[i].session_stats)
			pgs_free(ptr[i].session_stats);
	}
	pgs_free(ptr);
}
