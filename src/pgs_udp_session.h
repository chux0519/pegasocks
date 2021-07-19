#ifndef _PGS_UDP_SESSION
#define _PGS_UDP_SESSION

#include "pgs_local_server.h"

typedef struct pgs_udp_session_s {
	int fd;
	pgs_local_server_t *local_server;
} pgs_udp_session_t;

pgs_udp_session_t *pgs_udp_session_new(int fd,
				       pgs_local_server_t *local_server);
void pgs_udp_session_free(pgs_udp_session_t *session);
void pgs_udp_session_start(pgs_udp_session_t *session);

#endif
