#include "server/manager.h"
#include <assert.h>

pgs_server_manager_t *
pgs_server_manager_new(pgs_server_config_t *server_configs, int server_len)
{
	pgs_server_manager_t *ptr = malloc(sizeof(pgs_server_manager_t));
	ptr->server_stats = calloc(server_len, sizeof(pgs_server_stats_t));
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

/*
 * Get server config for session
 * not thread safe
 */
pgs_server_config_t *pgs_server_manager_get_config(pgs_server_manager_t *sm)
{
	assert(sm->cur_server_index < sm->server_len);
	return &sm->server_configs[sm->cur_server_index];
}
