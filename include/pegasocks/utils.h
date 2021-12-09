#ifndef _PGS_UTILS_H
#define _PGS_UTILS_H

#include <stddef.h>
#include <stdint.h>

// evdns helper
#define PGS_DNS_INIT(base, dns_base_ptr, config, logger, flag)                  \
	do {                                                                    \
		if ((config)->dns_servers->len > 0) {                           \
			*(dns_base_ptr) = evdns_base_new((base), 0);            \
			pgs_list_node_t *cur, *next;                            \
			pgs_list_foreach((config)->dns_servers, cur, next)      \
			{                                                       \
				pgs_logger_debug((logger),                      \
						 "Add DNS server: %s",          \
						 (const char *)cur->val);       \
				if (evdns_base_nameserver_ip_add(               \
					    *(dns_base_ptr),                    \
					    (const char *)cur->val) != 0)       \
					pgs_logger_error(                       \
						(logger),                       \
						"Failed to add DNS server: %s", \
						(const char *)cur->val);        \
			}                                                       \
		} else {                                                        \
			*(dns_base_ptr) = evdns_base_new((base), (flag));       \
		}                                                               \
		evdns_base_set_option(*(dns_base_ptr),                          \
				      "max-probe-timeout:", "5");               \
		evdns_base_set_option(*(dns_base_ptr),                          \
				      "probe-backoff-factor:", "1");            \
	} while (0)

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

#endif
