#ifndef _PGS_PEGAS_H
#define _PGS_PEGAS_H

#include "stdbool.h"

bool pgs_start(const char *config, const char *acl, int threads);

void pgs_stop();

#endif
