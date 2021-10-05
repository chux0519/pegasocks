#include "server/manager.h"
#include <assert.h>

pgs_server_manager_t *
pgs_server_manager_new(pgs_server_config_t *server_configs, int server_len)
{
	pgs_server_manager_t *ptr = malloc(sizeof(pgs_server_manager_t));
	ptr->server_stats = malloc(server_len * sizeof(pgs_server_stats_t));
	for (size_t i = 0; i < server_len; ++i) {
		ptr->server_stats[i].connect_delay = -1;
		ptr->server_stats[i].g204_delay = -1;
	}
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

/*
 * Get server metrics for session
 */
void pgs_sm_get_servers(pgs_server_manager_t *SM, char *out, int max_len,
			int *olen)
{
	JSON_Value *vroot = json_value_init_array();
	JSON_Array *aroot = json_value_get_array(vroot);

	for (int i = 0; i < SM->server_len; ++i) {
		JSON_Value *vserver = json_value_init_object();
		JSON_Object *oserver = json_value_get_object(vserver);
		json_object_set_number(oserver, "index", i);
		json_object_set_boolean(oserver, "active",
					i == SM->cur_server_index);
		json_object_set_number(oserver, "connect",
				       SM->server_stats[i].connect_delay);
		json_object_set_number(oserver, "g204",
				       SM->server_stats[i].g204_delay);
		json_object_set_string(oserver, "type",
				       SM->server_configs[i].server_type);
		json_object_set_string(oserver, "address",
				       SM->server_configs[i].server_address);
		json_object_set_number(oserver, "port",
				       SM->server_configs[i].server_port);
		json_array_append_value(aroot, vserver);
	}

	char *serialized_string = NULL;
	serialized_string = json_serialize_to_string_pretty(vroot);
	*olen = snprintf(out, max_len, "%s", serialized_string);
	json_free_serialized_string(serialized_string);
	json_value_free(vroot);
}

bool pgs_sm_set_server(pgs_server_manager_t *SM, int idx)
{
	if (idx < SM->server_len && idx >= 0) {
		SM->cur_server_index = idx;
		return true;
	}
	return false;
}
