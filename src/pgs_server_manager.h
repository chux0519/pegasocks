#ifndef _PGS_SERVER_MANAGER
#define _PGS_SERVER_MANAGER

#include "pgs_config.h"

typedef struct pgs_server_stats_s pgs_server_stats_t;
typedef struct pgs_server_manager_s pgs_server_manager_t;

struct pgs_server_stats_s {
	int connect_delay;
	int g204_delay;
	unsigned long up_speed;
	unsigned long down_speed;
};

struct pgs_server_manager_s {
	pgs_server_stats_t *server_stats;
	pgs_server_config_t *server_configs;
	int server_len;
	int cur_server_index;
};

pgs_server_manager_t *
pgs_server_manager_new(pgs_server_config_t *server_configs, int server_len);
void pgs_server_manager_free(pgs_server_manager_t *sm);

pgs_server_config_t *pgs_server_manager_get_config(pgs_server_manager_t *sm);

#endif
