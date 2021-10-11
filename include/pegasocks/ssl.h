#ifndef _PGS_SSL_H
#define _PGS_SSL_H

#include "config.h"

#include <event2/bufferevent_ssl.h>

struct pgs_ssl_ctx_s;

typedef struct pgs_ssl_ctx_s pgs_ssl_ctx_t;

pgs_ssl_ctx_t *pgs_ssl_ctx_new(pgs_config_t *config);
void pgs_ssl_ctx_free(pgs_ssl_ctx_t *ctx);

int pgs_session_outbound_ssl_bev_init(struct bufferevent **bev, int fd,
				      struct event_base *base,
				      pgs_ssl_ctx_t *ssl_ctx, const char *sni);

#endif
