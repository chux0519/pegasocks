#ifndef _CRM_SOCKS5
#define _CRM_SOCKS5

#include "crm_core.h"
#include "crm_conn.h"

typedef struct crm_socks5_s crm_socks5_t;
typedef enum { AUTH, CMD, PROXY } crm_socks5_states;

struct crm_socks5_s {
	crm_conn_t conn;
	crm_socks5_states state;
};

#endif
