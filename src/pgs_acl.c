#include "pgs_acl.h"

#include <stdlib.h>
#include <string.h>

pgs_acl_t *pgs_acl_new(pgs_acl_mode mode, const char *path)
{
	pgs_acl_t *ptr = malloc(sizeof(pgs_acl_t));
	ptr->mode = mode;
	ipset_init(&ptr->v4set);
	ipset_init(&ptr->v6set);
	cork_dllist_init(&ptr->rules);

	// TODO: load acl file from path

	return ptr;
}

void pgs_acl_add_rule(pgs_acl_t *acl, const char *raw)
{
	pgs_acl_rule_t *rule = pgs_acl_rule_new(raw);
	cork_dllist_add(&acl->rules, &rule->entry);
}

void pgs_acl_free(pgs_acl_t *ptr)
{
	ipset_done(&ptr->v4set);
	ipset_done(&ptr->v6set);

	struct cork_dllist_item *iter;
	while ((iter = cork_dllist_head(&ptr->rules)) != NULL) {
		pgs_acl_rule_t *rule =
			cork_container_of(iter, pgs_acl_rule_t, entry);
		cork_dllist_remove(&rule->entry);
		pgs_acl_rule_free(rule);
	}
	free(ptr);
	ptr = NULL;
}

pgs_acl_rule_t *pgs_acl_rule_new(const char *raw)
{
	pgs_acl_rule_t *ptr = malloc(sizeof(pgs_acl_rule_t));
	ptr->raw = strdup(raw);
	ptr->pattern = re_compile(ptr->raw);
	return ptr;
}

void pgs_acl_rule_free(pgs_acl_rule_t *ptr)
{
	free(ptr->raw);
	free(ptr);
	ptr = NULL;
}

bool pgs_acl_match_host(pgs_acl_t *acl, const char *host)
{
	struct cork_ip addr;
	int err = cork_ip_init(&addr, host);

	if (err) {
		int match_length;
		int match_idx = -1;
		struct cork_dllist_item *curr, *next;
		pgs_acl_rule_t *rule;
		cork_dllist_foreach(&acl->rules, curr, next, pgs_acl_rule_t,
				    rule, entry)
		{
			match_idx =
				re_matchp(rule->pattern, host, &match_length);
			if (match_idx != -1) {
				return true;
			}
		}
		return false;
	}

	if (addr.version == 4) {
		return ipset_contains_ipv4(&acl->v4set, &(addr.ip.v4));
	} else if (addr.version == 6) {
		return ipset_contains_ipv6(&acl->v6set, &(addr.ip.v6));
	}
	return false;
}
