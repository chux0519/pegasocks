#ifndef _PGS_SOCKS5
#define _PGS_SOCKS5

#include "pgs_core.h"

typedef struct pgs_socks5_s pgs_socks5_t;
typedef enum { AUTH, CMD, PROXY, ERR } pgs_socks5_states;

struct pgs_socks5_s {
	pgs_socks5_states state;
	char err_msg[64];
	pgs_buf_t *rbuf;
	pgs_buf_t *wbuf;
	pgs_size_t *read_bytes_ptr; // read only
	pgs_size_t *write_bytes_ptr;
};

void pgs_socks5_step(pgs_socks5_t *s);

#endif
