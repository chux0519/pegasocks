#ifndef _PGS_SERVER_MANAGER
#define _PGS_SERVER_MANAGER

#include "pgs_config.h"
#include "pgs_mpsc.h"

#define MAX_SESSION_STATS_SIZE 16

typedef struct pgs_server_stats_s pgs_server_stats_t;
typedef struct pgs_server_session_stats_s pgs_server_session_stats_t;
typedef struct pgs_server_manager_s pgs_server_manager_t;
typedef struct pgs_session_stats_msg_s pgs_session_stats_msg_t;

struct pgs_server_session_stats_s {
	time_t start;
	time_t end;
	pgs_size_t send;
	pgs_size_t recv;
};

struct pgs_server_stats_s {
	int connect_delay;
	int g204_delay;
	pgs_server_session_stats_t *session_stats;
	pgs_size_t session_stats_index;
};

struct pgs_server_manager_s {
	pgs_mpsc_t *mpsc;
	pgs_server_stats_t *server_stats;
	pgs_server_config_t *server_configs;
	int server_len;
	int cur_server_index;
};

struct pgs_session_stats_msg_s {
	pgs_server_session_stats_t *data;
	int server_config_index;
};

pgs_server_manager_t *
pgs_server_manager_new(pgs_mpsc_t *mpsc, pgs_server_config_t *server_configs,
		       int server_len);
void pgs_server_manager_free(pgs_server_manager_t *sm);

void pgs_server_manager_tryrecv(pgs_server_manager_t *sm);

pgs_server_config_t *pgs_server_manager_get_config(pgs_server_manager_t *sm);

void pgs_server_stats_init(pgs_server_stats_t *ptr, int len);
void pgs_server_stats_free(pgs_server_stats_t *ptr, int len);

pgs_session_stats_msg_t *pgs_session_stats_msg_new(time_t start, time_t end,
						   pgs_size_t send,
						   pgs_size_t recv,
						   int config_idx);
void pgs_session_stats_msg_send(pgs_session_stats_msg_t *msg,
				pgs_server_manager_t *sm);
void pgs_session_stats_msg_free(pgs_session_stats_msg_t *msg);

#endif
