#ifndef _CRM_MPSC
#define _CRM_MPSC

#include "stdatomic.h"
#include "crm_core.h"

typedef struct crm_mpsc_s crm_mpsc_t;

struct crm_mpsc_s {
	_Atomic long count;
	_Atomic long in_pos;
	long out_pos; // using from one thread(consumer), so thread safe
	long max;
	void *_Atomic *slots;
};

crm_mpsc_t *crm_mpsc_new(long size);

void crm_mpsc_free(crm_mpsc_t *mpsc);

bool crm_mpsc_send(crm_mpsc_t *mpsc, void *data);

void *crm_mpsc_recv(crm_mpsc_t *mpsc);

#endif

