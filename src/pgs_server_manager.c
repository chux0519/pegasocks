#include "pgs_server_manager.h"
#include <assert.h>

pgs_server_manager_t *
pgs_server_manager_new(pgs_mpsc_t *mpsc, pgs_server_config_t *server_configs,
		       int server_len)
{
	pgs_server_manager_t *ptr = malloc(sizeof(pgs_server_manager_t));
	ptr->mpsc = mpsc;
	ptr->server_stats = calloc(server_len, sizeof(pgs_server_stats_t));
	pgs_server_stats_init(ptr->server_stats, server_len);
	ptr->server_configs = server_configs;
	ptr->server_len = server_len;
	ptr->cur_server_index = 0;
	return ptr;
}

void pgs_server_manager_free(pgs_server_manager_t *ptr)
{
	free(ptr->server_stats);
	free(ptr);
}

void pgs_server_manager_tryrecv(pgs_server_manager_t *ptr)
{
	while (true) {
		pgs_session_stats_msg_t *msg = pgs_mpsc_recv(ptr->mpsc);
		if (msg == NULL)
			return;

		pgs_server_stats_t *stats =
			&ptr->server_stats[msg->server_config_index];
		pgs_server_session_stats_t *session_stats =
			&stats->session_stats[stats->session_stats_index];

		session_stats->start = msg->data->start;
		session_stats->end = msg->data->end;
		session_stats->recv = msg->data->recv;
		session_stats->send = msg->data->send;
		stats->session_stats_index += 1;
		if (stats->session_stats_index == MAX_SESSION_STATS_SIZE)
			stats->session_stats_index = 0;

		pgs_session_stats_msg_free(msg);
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
			malloc(MAX_SESSION_STATS_SIZE *
			       sizeof(pgs_server_session_stats_t));
		memzero(ptr[i].session_stats,
			MAX_SESSION_STATS_SIZE *
				sizeof(pgs_server_session_stats_t));
		ptr[i].session_stats_index = 0;
	}
}

void pgs_server_stats_free(pgs_server_stats_t *ptr, int len)
{
	for (int i = 0; i < len; i++) {
		if (ptr[i].session_stats)
			free(ptr[i].session_stats);
	}
	free(ptr);
}

pgs_session_stats_msg_t *pgs_session_stats_msg_new(time_t start, time_t end,
						   uint64_t send, uint64_t recv,
						   int config_idx)
{
	pgs_server_session_stats_t *data =
		malloc(sizeof(pgs_server_session_stats_t));
	data->start = start;
	data->end = end;
	data->send = send;
	data->recv = recv;
	pgs_session_stats_msg_t *ptr = malloc(sizeof(pgs_session_stats_msg_t));
	ptr->server_config_index = config_idx;
	ptr->data = data;
	return ptr;
}

void pgs_session_stats_msg_send(pgs_session_stats_msg_t *msg,
				pgs_server_manager_t *sm)
{
	pgs_mpsc_send(sm->mpsc, msg);
}

void pgs_session_stats_msg_free(pgs_session_stats_msg_t *msg)
{
	if (msg->data)
		free(msg->data);
	free(msg);
}
