#ifndef _PGS_PEGAS_H
#define _PGS_PEGAS_H

#include "stdbool.h"

#ifndef PGS_VERSION
#define PGS_VERSION "v0.0.0-develop"
#endif

#ifdef __cplusplus
extern "C" {
#endif

bool pgs_start(const char *config, const char *acl, int threads,
	       void (*shutdown)());
void pgs_stop();

void pgs_get_version(char *version);

/*
 * pgs_get_servers will encode metrics as json string to `out`
 * and set the length of it to `olen`
 * */
void pgs_get_servers(char *out, int max_len, int *olen);
bool pgs_set_server(int idx);

#ifdef __cplusplus
}
#endif

#endif
