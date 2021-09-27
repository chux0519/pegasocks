#ifndef _PGS_SERVER_MANAGER_H
#define _PGS_SERVER_MANAGER_H

#include <stdint.h>

#include "defs.h"
#include "config.h"

#define MAX_SESSION_STATS_SIZE 16

typedef struct pgs_server_stats_s {
	double connect_delay;
	double g204_delay;
} pgs_server_stats_t;

typedef struct pgs_server_manager_s {
	pgs_server_stats_t *server_stats;
	pgs_server_config_t *server_configs;
	int server_len;
	int cur_server_index;
} pgs_server_manager_t;

pgs_server_manager_t *
pgs_server_manager_new(pgs_server_config_t *server_configs, int server_len);
void pgs_server_manager_free(pgs_server_manager_t *sm);

pgs_server_config_t *pgs_server_manager_get_config(pgs_server_manager_t *sm);

#endif
