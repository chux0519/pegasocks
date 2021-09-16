#include "pgs_acl.h"

#include <ipset/ipset.h>

static struct ip_set white_list_ipv4;
static struct ip_set white_list_ipv6;

static struct ip_set black_list_ipv4;
static struct ip_set black_list_ipv6;

static int acl_mode = BLACK_LIST;

int pgs_acl_init(const char *path)
{
	ipset_init_library();

	ipset_init(&white_list_ipv4);
	ipset_init(&white_list_ipv6);
	ipset_init(&black_list_ipv4);
	ipset_init(&black_list_ipv6);

	return 0;
}

void pgs_acl_free()
{
	ipset_done(&black_list_ipv4);
	ipset_done(&black_list_ipv6);
	ipset_done(&white_list_ipv4);
	ipset_done(&white_list_ipv6);
}
