#ifndef _PGS_CONN
#define _PGS_CONN

#include "pgs_core.h"

typedef struct pgs_conn_s pgs_conn_t;

struct pgs_conn_s {
	pgs_socket_t fd;
	pgs_buf_t rbuf[_PGS_READ_BUFSZIE];
	pgs_buf_t wbuf[_PGS_BUFSIZE];
	pgs_size_t read_bytes;
	pgs_size_t write_bytes;
};

pgs_conn_t *pgs_conn_new(pgs_socket_t fd);

void pgs_conn_free(pgs_conn_t *conn);

#endif

