#ifndef _PGS_UTILS_H
#define _PGS_UTILS_H

#include <stddef.h>

typedef struct pgs_list_node_s {
	void *val;

	struct pgs_list_node_s *prev;
	struct pgs_list_node_s *next;
} pgs_list_node_t;

typedef struct pgs_list_s {
	pgs_list_node_t *head;
	pgs_list_node_t *tail;
	size_t len;

	void (*free)(void *val);
} pgs_list_t;

pgs_list_node_t *pgs_list_node_new(void *val);

pgs_list_t *pgs_list_new();
void pgs_list_free(pgs_list_t *ptr);

pgs_list_node_t *pgs_list_add(pgs_list_t *ptr, pgs_list_node_t *node);

void pgs_list_del(pgs_list_t *ptr, pgs_list_node_t *node);

#endif
