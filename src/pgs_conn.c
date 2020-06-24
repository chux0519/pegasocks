#include "pgs_conn.h"

pgs_conn_t *pgs_conn_new(pgs_socket_t fd)
{
	pgs_conn_t *ptr = pgs_malloc(sizeof(pgs_conn_t));
	pgs_memzero(ptr->rbuf, sizeof(ptr->rbuf));
	pgs_memzero(ptr->wbuf, sizeof(ptr->wbuf));
	ptr->fd = fd;

	return ptr;
}

void pgs_conn_free(pgs_conn_t *conn)
{
	pgs_free(conn);
}
