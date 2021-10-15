#include "utils.h"

#include <stdlib.h>

// ===================== buffer
pgs_buffer_t *pgs_buffer_new()
{
	pgs_buffer_t *ptr = malloc(sizeof(pgs_buffer_t));
	ptr->buffer = malloc(PGS_DEFAULT_BUFSIZE);
	ptr->cap = PGS_DEFAULT_BUFSIZE;
	return ptr;
}

void pgs_buffer_free(pgs_buffer_t *ptr)
{
	if (ptr) {
		if (ptr->buffer)
			free(ptr->buffer);
		free(ptr);
	}
}

void pgs_buffer_ensure(pgs_buffer_t *ptr, size_t n)
{
	if (ptr->cap >= n)
		return;
	int times = 1 << 1;

	while (times * ptr->cap < n) {
		times <<= 1;
	}
	ptr->cap = times * ptr->cap;
	ptr->buffer = realloc(ptr->buffer, ptr->cap);
}

// ====================== list

pgs_list_node_t *pgs_list_node_new(void *val)
{
	pgs_list_node_t *ptr = malloc(sizeof(pgs_list_node_t));
	ptr->prev = NULL;
	ptr->next = NULL;
	ptr->val = val;
	return ptr;
}

pgs_list_t *pgs_list_new()
{
	pgs_list_t *ptr = malloc(sizeof(pgs_list_t));

	ptr->head = NULL;
	ptr->tail = NULL;
	ptr->free = NULL;
	ptr->len = 0;

	return ptr;
}

void pgs_list_free(pgs_list_t *ptr)
{
	while (ptr->len) {
		pgs_list_del(ptr, ptr->head);
	}
	free(ptr);
}

pgs_list_node_t *pgs_list_add(pgs_list_t *ptr, pgs_list_node_t *node)
{
	if (!node)
		return NULL;
	if (ptr->len) {
		node->prev = ptr->tail;
		node->next = NULL;
		ptr->tail->next = node;
		ptr->tail = node;
	} else {
		ptr->head = node;
		ptr->tail = node;
		node->prev = NULL;
		node->next = NULL;
	}

	++ptr->len;
	return node;
}

void pgs_list_del(pgs_list_t *ptr, pgs_list_node_t *node)
{
	if (node->prev) {
		node->prev->next = node->next;
	} else {
		ptr->head = node->next;
	}
	if (node->next) {
		node->next->prev = node->prev;
	} else {
		ptr->tail = node->prev;
	}

	if (ptr->free)
		ptr->free(node->val);

	free(node);

	--ptr->len;
}
