#ifndef _PGS_ACL
#define _PGS_ACL

#include <stdbool.h>

#include <ipset/ipset.h>
#include <libcork/ds/dllist.h>
#include <tiny-regex-c/re.h>

typedef enum {
	PROXY_ALL_BYPASS_LIST,
	BYPASS_ALL_PROXY_LIST,
} pgs_acl_mode;

typedef struct pgs_acl_s {
	pgs_acl_mode mode;
	struct ip_set v4set;
	struct ip_set v6set;
	struct cork_dllist rules;
} pgs_acl_t;

typedef struct pgs_acl_rule_s {
	char *raw;
	re_t pattern;
	struct cork_dllist_item entry;
} pgs_acl_rule_t;

pgs_acl_t *pgs_acl_new(pgs_acl_mode mode, const char *path);

void pgs_acl_add_rule(pgs_acl_t *acl, const char *raw);

void pgs_acl_free(pgs_acl_t *acl);

pgs_acl_rule_t *pgs_acl_rule_new(const char *raw);

void pgs_acl_rule_free(pgs_acl_rule_t *rule);

bool pgs_acl_match_host(pgs_acl_t *acl, const char *host);

#endif
