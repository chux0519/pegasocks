#include "crm_mpsc.h"
#include "assert.h"

crm_mpsc_t *crm_mpsc_new(long size)
{
	crm_mpsc_t *ptr = crm_malloc(sizeof(crm_mpsc_t));
	ptr->count = ATOMIC_VAR_INIT(0);
	ptr->in_pos = ATOMIC_VAR_INIT(0);

	ptr->out_pos = 0;
	ptr->max = size;
	ptr->slots = crm_calloc(size, sizeof(void *));
	return ptr;
}

void crm_mpsc_free(crm_mpsc_t *mpsc)
{
	crm_free(mpsc->slots);
	crm_free(mpsc);
}

bool crm_mpsc_send(crm_mpsc_t *mpsc, void *data)
{
	long count = atomic_fetch_add_explicit(&mpsc->count, 1,
					       memory_order_acquire);
	if (count >= mpsc->max) {
		atomic_fetch_sub_explicit(&mpsc->count, 1,
					  memory_order_release);
		return false;
	}

	long in_pos = atomic_fetch_add_explicit(&mpsc->in_pos, 1,
						memory_order_acquire);
	void *rv = atomic_exchange_explicit(&mpsc->slots[in_pos % mpsc->max],
					    data, memory_order_release);
	assert(rv == NULL);
	return true;
}

void *crm_mpsc_recv(crm_mpsc_t *mpsc)
{
	void *ret = atomic_exchange_explicit(&mpsc->slots[mpsc->out_pos], NULL,
					     memory_order_acquire);
	if (!ret) {
		return NULL;
	}
	if (++mpsc->out_pos >= mpsc->max)
		mpsc->out_pos = 0;
	long r = atomic_fetch_sub_explicit(&mpsc->count, 1,
					   memory_order_release);
	assert(r > 0);
	return ret;
}

