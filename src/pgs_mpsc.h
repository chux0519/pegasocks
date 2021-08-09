#ifndef _PGS_MPSC
#define _PGS_MPSC

#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>

typedef struct pgs_mpsc_s pgs_mpsc_t;

struct pgs_mpsc_s {
	_Atomic long count;
	_Atomic long in_pos;
	long out_pos; // using from one thread(consumer), so thread safe
	long max;
	void *_Atomic *slots;
};

pgs_mpsc_t *pgs_mpsc_new(long size);

void pgs_mpsc_free(pgs_mpsc_t *mpsc);

bool pgs_mpsc_send(pgs_mpsc_t *mpsc, void *data);

void *pgs_mpsc_recv(pgs_mpsc_t *mpsc);

#endif
