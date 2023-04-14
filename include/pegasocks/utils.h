#ifndef _PGS_UTILS_H
#define _PGS_UTILS_H

#include <stddef.h>
#include <stdint.h>

#define PGS_DEFAULT_BUFSIZE 1 * 1024

// ======================== buffers for codec
typedef struct pgs_buffer_s {
	uint8_t *buffer;
	size_t cap;
} pgs_buffer_t;

pgs_buffer_t *pgs_buffer_new();
void pgs_buffer_free(pgs_buffer_t *);
void pgs_buffer_ensure(pgs_buffer_t *, size_t);

// ======================== list for sessions and outbound metrics requests
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
void pgs_list_del_val(pgs_list_t *ptr, void *val);

#define pgs_list_foreach(list, cur, _next)                                     \
	for ((cur) = (list)->head, (_next) = (cur) ? ((cur)->next) : (NULL);   \
	     (cur) != NULL;                                                    \
	     (cur) = (_next), (_next) = (cur) ? ((cur)->next) : (NULL))

#define pgs_list_foreach_backward(list, cur, _prev)                            \
	for ((cur) = (list)->tail, (_prev) = (cur) ? ((cur)->prev) : (NULL);   \
	     (cur) != NULL;                                                    \
	     (cur) = (_prev), (_prev) = (cur) ? ((cur)->prev) : (NULL))

#endif
