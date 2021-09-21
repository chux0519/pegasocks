#ifndef _PGS_SSL_H
#define _PGS_SSL_H

#include <event2/bufferevent_ssl.h>

struct pgs_ssl_ctx_s;
struct pgs_ssl_s;

typedef struct pgs_ssl_ctx_s pgs_ssl_ctx_t;
typedef struct pgs_ssl_s pgs_ssl_t;

pgs_ssl_ctx_t *pgs_ssl_ctx_new();
void pgs_ssl_ctx_free(pgs_ssl_ctx_t *ctx);
pgs_ssl_t *pgs_ssl_new(pgs_ssl_ctx_t *ctx, void *hostname);
void pgs_ssl_close(pgs_ssl_t *ssl);
int pgs_session_outbound_ssl_bev_init(struct bufferevent **bev,
				      struct event_base *base,
				      pgs_ssl_ctx_t *ssl_ctx, const char *sni);
void pgs_free_bev_ssl_ctx(struct bufferevent *bev);

#endif
