#ifndef _PGS_ACL_H
#define _PGS_ACL_H

#include <stdbool.h>

struct pgs_acl_s;
typedef struct pgs_acl_s pgs_acl_t;

struct pgs_acl_rule_s;
typedef struct pgs_acl_rule_s pgs_acl_rule_t;

typedef enum {
	PROXY_ALL_BYPASS_LIST,
	BYPASS_ALL_PROXY_LIST,
} pgs_acl_mode;

pgs_acl_t *pgs_acl_new(const char *path);

void pgs_acl_add_rule(pgs_acl_t *acl, const char *raw);

pgs_acl_mode pgs_acl_get_mode(pgs_acl_t *ptr);

void pgs_acl_free(pgs_acl_t *acl);

pgs_acl_rule_t *pgs_acl_rule_new(const char *raw);

void pgs_acl_rule_free(pgs_acl_rule_t *rule);

bool pgs_acl_match_host(pgs_acl_t *acl, const char *host);

#endif
