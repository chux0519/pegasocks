#ifndef _CRM_CONN
#define _CRM_CONN

#include "crm_core.h"

typedef struct crm_conn_s crm_conn_t;

struct crm_conn_s {
	crm_socket_t fd;
	crm_buf_t rbuf;
	crm_buf_t wbuf;
};

#endif

