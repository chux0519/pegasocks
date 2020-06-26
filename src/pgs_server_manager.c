#include "pgs_server_manager.h"
#include "pgs_core.h"
#include <assert.h>

pgs_server_manager_t *
pgs_server_manager_new(pgs_server_config_t *server_configs, int server_len)
{
	pgs_server_manager_t *ptr = pgs_malloc(sizeof(pgs_server_manager_t));
	ptr->server_stats = pgs_calloc(server_len, sizeof(pgs_server_stats_t));
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

/*
 * Get server config for session
 * not thread safe
 */
pgs_server_config_t *pgs_server_manager_get_config(pgs_server_manager_t *sm)
{
	assert(sm->cur_server_index < sm->server_len);
	return &sm->server_configs[sm->cur_server_index];
}
