#ifndef _PGS_METRICS
#define _PGS_METRICS

#include "pgs_server_manager.h"
#include "pgs_ev.h"
#include "pgs_session.h"

void get_metrics_connect(pgs_ev_base_t *base, pgs_server_manager_t *sm,
			 int idx);
void get_metrics_g204(pgs_ev_base_t *base, pgs_server_manager_t *sm, int idx);

#endif
