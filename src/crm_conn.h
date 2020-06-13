#ifndef _CRM_CONN
#define _CRM_CONN

#include "crm_core.h"

typedef struct crm_conn_s crm_conn_t;

struct crm_conn_s {
	crm_socket_t fd;
	crm_buf_t rbuf[_CRM_READ_BUFSZIE];
	crm_buf_t wbuf[_CRM_BUFSIZE];
	crm_size_t read_bytes;
	crm_size_t write_bytes;
};

crm_conn_t *crm_conn_new(crm_socket_t fd);

void crm_conn_free(crm_conn_t *conn);

#endif

