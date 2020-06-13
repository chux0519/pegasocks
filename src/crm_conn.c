#include "crm_conn.h"

crm_conn_t *crm_conn_new(crm_socket_t fd)
{
	crm_conn_t *ptr = crm_malloc(sizeof(crm_conn_t));
	crm_memzero(ptr->rbuf, sizeof(ptr->rbuf));
	crm_memzero(ptr->wbuf, sizeof(ptr->wbuf));
	ptr->fd = fd;

	return ptr;
}

void crm_conn_free(crm_conn_t *conn)
{
	crm_free(conn);
}
