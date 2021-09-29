#ifndef _PGS_PEGAS_H
#define _PGS_PEGAS_H

#include "stdbool.h"

bool pgs_init(const char *config, const char *acl, int threads);

bool pgs_start();

void pgs_stop();

void pgs_clean();

#endif
