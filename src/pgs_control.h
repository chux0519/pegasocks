#ifndef _PGS_CONTROL
#define _PGS_CONTROL

#include "pgs_server_manager.h"
#include "pgs_ev.h"

// PING - PONG
// GET METRICS
// GET SERVER
// SET SERVER $number
// reload
// stop

typedef struct pgs_control_server_ctx_s pgs_control_server_ctx_t;

struct pgs_control_server_ctx_s {
	pgs_ev_base_t *base;
	pgs_server_manager_t *sm;
	pgs_logger_t *logger;
	const pgs_config_t *config;
	pgs_listener_t *listener;
};

pgs_control_server_ctx_t *pgs_control_server_ctx_new();
void pgs_control_server_ctx_destroy(pgs_control_server_ctx_t *ptr);

void pgs_control_server_start(int fd, pgs_ev_base_t *base,
			      pgs_server_manager_t *sm, pgs_logger_t *logger,
			      const pgs_config_t *config);

#endif
