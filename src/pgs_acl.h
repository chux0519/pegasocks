#ifndef _PGS_ACL
#define _PGS_ACL

#define BLACK_LIST 0
#define WHITE_LIST 1

int pgs_acl_init(const char *path);
void pgs_acl_free();

int pgs_acl_match_host(const char *ip);
int pgs_acl_add_ip(const char *ip);
int pgs_acl_remove_ip(const char *ip);

int pgs_get_acl_mode();

#endif
