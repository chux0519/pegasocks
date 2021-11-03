#include "acl.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include <ipset/ipset.h>
#include <libcork/ds/dllist.h>
#include <pcre.h>

#define LINE_BUFF_SIZE 256

typedef struct pgs_inner_acl_s {
	pgs_acl_mode mode;
	struct ip_set v4set;
	struct ip_set v6set;
	struct cork_dllist rules;
} pgs_inner_acl_t;

/* store two types of acl
 * if domain in bypass_acl/proxy_acl, directly bypass/proxy without DNS resolve. 
 * Otherwise we query DNS, then match again */
struct pgs_acl_s {
	/* proxy all, bypass list */
	pgs_inner_acl_t *bypass_acl;
	/* bypass all, proxy list */
	pgs_inner_acl_t *proxy_acl;
};

struct pgs_acl_rule_s {
	char *raw;
	pcre *pattern;
	struct cork_dllist_item entry;
};

static void pgs_acl_add_rule(pgs_inner_acl_t *acl, const char *raw)
{
	pgs_acl_rule_t *rule = pgs_acl_rule_new(raw);
	cork_dllist_add(&acl->rules, &rule->entry);
}

static pgs_acl_mode pgs_acl_get_mode(pgs_inner_acl_t *ptr)
{
	return ptr->mode;
}

static void parse_addr_cidr(const char *str, char *host, int *cidr)
{
	int ret = -1;
	char *pch;

	pch = strchr(str, '/');
	while (pch != NULL) {
		ret = pch - str;
		pch = strchr(pch + 1, '/');
	}
	if (ret == -1) {
		strcpy(host, str);
		*cidr = -1;
	} else {
		memcpy(host, str, ret);
		host[ret] = '\0';
		*cidr = atoi(str + ret + 1);
	}
}

static char *trimwhitespace(char *str)
{
	char *end;

	while (isspace((unsigned char)*str))
		str++;

	if (*str == 0)
		return str;

	end = str + strlen(str) - 1;
	while (end > str && isspace((unsigned char)*end))
		end--;

	*(end + 1) = 0;

	return str;
}

pgs_acl_t *pgs_acl_new(const char *path)
{
	pgs_acl_t *ptr = malloc(sizeof(pgs_acl_t));
	ptr->bypass_acl = malloc(sizeof(pgs_inner_acl_t));
	ptr->proxy_acl = malloc(sizeof(pgs_inner_acl_t));

	ptr->proxy_acl->mode = BYPASS_ALL_PROXY_LIST;
	ptr->bypass_acl->mode = PROXY_ALL_BYPASS_LIST;

	ipset_init(&ptr->proxy_acl->v4set);
	ipset_init(&ptr->proxy_acl->v6set);
	cork_dllist_init(&ptr->proxy_acl->rules);

	ipset_init(&ptr->bypass_acl->v4set);
	ipset_init(&ptr->bypass_acl->v6set);
	cork_dllist_init(&ptr->bypass_acl->rules);

	FILE *fd = fopen(path, "r");
	if (fd == NULL)
		goto error;

	char buff[LINE_BUFF_SIZE];

	pgs_inner_acl_t *acl = NULL;

	// parsing logic is modifed from
	// https://github.com/shadowsocks/shadowsocks-libev/blob/master/src/acl.c#L133
	while (!feof(fd)) {
		if (fgets(buff, LINE_BUFF_SIZE, fd)) {
			// Discards the whole line if longer than 255 characters
			int long_line = 0; // 1: Long  2: Error
			while ((strlen(buff) == 255) && (buff[254] != '\n')) {
				long_line = 1;
				if (fgets(buff, LINE_BUFF_SIZE, fd) == NULL) {
					long_line = 2;
					break;
				}
			}
			if (long_line) {
				continue;
			}

			// Trim the newline
			int len = strlen(buff);
			if (len > 0 && buff[len - 1] == '\n') {
				buff[len - 1] = '\0';
			}

			char *comment = strchr(buff, '#');
			if (comment) {
				*comment = '\0';
			}

			char *line = trimwhitespace(buff);
			if (strlen(line) == 0) {
				continue;
			}

			// notice: outbound_block_list is not supported
			if (strcmp(line, "[black_list]") == 0 ||
			    strcmp(line, "[bypass_list]") == 0) {
				acl = ptr->bypass_acl;
				// ptr->mode = PROXY_ALL_BYPASS_LIST;
				continue;
			} else if (strcmp(line, "[accept_all]") == 0 ||
				   strcmp(line, "[proxy_all]") == 0) {
				acl = ptr->bypass_acl;
				// ptr->mode = PROXY_ALL_BYPASS_LIST;
				continue;
			} else if (strcmp(line, "[white_list]") == 0 ||
				   strcmp(line, "[proxy_list]") == 0) {
				acl = ptr->proxy_acl;
				// ptr->mode = BYPASS_ALL_PROXY_LIST;
				continue;
			} else if (strcmp(line, "[reject_all]") == 0 ||
				   strcmp(line, "[bypass_all]") == 0) {
				acl = ptr->proxy_acl;
				// ptr->mode = BYPASS_ALL_PROXY_LIST;
				continue;
			}

			char host[LINE_BUFF_SIZE];
			int cidr;
			parse_addr_cidr(line, host, &cidr);

			struct cork_ip addr;
			int err = cork_ip_init(&addr, host);
			if (!err) {
				if (addr.version == 4) {
					if (cidr >= 0) {
						ipset_ipv4_add_network(
							&acl->v4set,
							&(addr.ip.v4), cidr);
					} else {
						ipset_ipv4_add(&acl->v4set,
							       &(addr.ip.v4));
					}
				} else if (addr.version == 6) {
					if (cidr >= 0) {
						ipset_ipv6_add_network(
							&acl->v6set,
							&(addr.ip.v6), cidr);
					} else {
						ipset_ipv6_add(&acl->v6set,
							       &(addr.ip.v6));
					}
				}
			} else {
				pgs_acl_add_rule(acl, line);
			}
		}
	}

	fclose(fd);

	return ptr;

error:
	fclose(fd);
	pgs_acl_free(ptr);
	return NULL;
}

static void pgs_inner_acl_free(pgs_inner_acl_t *ptr)
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

void pgs_acl_free(pgs_acl_t *ptr)
{
	if (ptr->bypass_acl)
		pgs_inner_acl_free(ptr->bypass_acl);
	if (ptr->proxy_acl)
		pgs_inner_acl_free(ptr->proxy_acl);
	if (ptr)
		free(ptr);
}

pgs_acl_rule_t *pgs_acl_rule_new(const char *raw)
{
	pgs_acl_rule_t *ptr = calloc(1, sizeof(pgs_acl_rule_t));
	ptr->raw = strdup(raw);

	const char *reerr;
	int reerroffset;
	ptr->pattern = pcre_compile(ptr->raw, 0, &reerr, &reerroffset, NULL);
	if (ptr->pattern == NULL)
		goto error;
	return ptr;

error:
	pgs_acl_rule_free(ptr);
	return NULL;
}

void pgs_acl_rule_free(pgs_acl_rule_t *ptr)
{
	free(ptr->raw);
	free(ptr);
	ptr = NULL;
}

static bool pgs_inner_acl_match_host(pgs_inner_acl_t *acl, const char *host)
{
	struct cork_ip addr;
	int err = cork_ip_init(&addr, host);

	if (err) {
		int host_len = strlen(host);

		struct cork_dllist_item *curr, *next;
		pgs_acl_rule_t *rule;
		cork_dllist_foreach(&acl->rules, curr, next, pgs_acl_rule_t,
				    rule, entry)
		{
			if (pcre_exec(rule->pattern, NULL, host, host_len, 0, 0,
				      NULL, 0) >= 0)
				return true;
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

bool pgs_acl_match_host_bypass(pgs_acl_t *acl, const char *host)
{
	/* proxy all bypass list, if match, we bypass it */
	return pgs_inner_acl_match_host(acl->bypass_acl, host);
}

bool pgs_acl_match_host_proxy(pgs_acl_t *acl, const char *host)
{
	/* bypass all proxy list, if match, we proxy it */
	return pgs_inner_acl_match_host(acl->proxy_acl, host);
}
