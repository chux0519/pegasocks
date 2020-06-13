#ifndef _CRM_SOCKS5
#define _CRM_SOCKS5

#include "crm_core.h"

typedef struct crm_socks5_s crm_socks5_t;
typedef enum { AUTH, CMD, PROXY, ERR } crm_socks5_states;

struct crm_socks5_s {
	crm_socks5_states state;
	char err_msg[64];
	crm_buf_t *rbuf;
	crm_buf_t *wbuf;
	crm_size_t *read_bytes_ptr; // read only
	crm_size_t *write_bytes_ptr;
};

void crm_socks5_step(crm_socks5_t *s);

#endif
