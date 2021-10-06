#ifndef _PGS_UTILS_H
#define _PGS_UTILS_H

#include <stddef.h>

// evdns helper
#define PGS_DNS_INIT(base, dns_base_ptr, config, logger)                       \
	do {                                                                   \
		if ((config)->dns_server) {                                    \
			*(dns_base_ptr) = evdns_base_new((base), 0);           \
			if (evdns_base_nameserver_ip_add(                      \
				    *(dns_base_ptr), (config)->dns_server) !=  \
			    0)                                                 \
				pgs_logger_error(                              \
					(logger),                              \
					"Failed to set DNS server: %s",        \
					(config)->dns_server);                 \
		} else {                                                       \
			*(dns_base_ptr) = evdns_base_new(                      \
				(base), EVDNS_BASE_INITIALIZE_NAMESERVERS);    \
		}                                                              \
		evdns_base_set_option(*(dns_base_ptr),                         \
				      "max-probe-timeout:", "5");              \
		evdns_base_set_option(*(dns_base_ptr),                         \
				      "probe-backoff-factor:", "1");           \
	} while (0)

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

#endif
