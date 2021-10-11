#ifndef _PGS_PEGAS_H
#define _PGS_PEGAS_H

#include "stdbool.h"

#ifdef __cplusplus
extern "C" {
#endif

bool pgs_start(const char *config, const char *acl, int threads,
	       void (*shutdown)());
void pgs_stop();

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
