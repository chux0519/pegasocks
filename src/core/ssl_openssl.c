#include "core/defs.h"
#include "core/ssl.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

struct pgs_ssl_ctx_s {
	SSL_CTX *_;
};

struct pgs_ssl_s {
	SSL *_;
};

// default to openssl
pgs_ssl_ctx_t *pgs_ssl_ctx_new()
{
	pgs_ssl_ctx_t *ptr = malloc(sizeof(pgs_ssl_ctx_t));
	ptr->_ = NULL;

	OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
				 OPENSSL_INIT_LOAD_CRYPTO_STRINGS,
			 NULL);
	if ((ptr->_ = SSL_CTX_new(SSLv23_client_method()))) {
		SSL_CTX_set_verify(ptr->_, SSL_VERIFY_NONE, NULL);
		SSL_CTX_set_verify_depth(ptr->_, 0);
		SSL_CTX_set_mode(ptr->_, SSL_MODE_AUTO_RETRY);
		SSL_CTX_set_session_cache_mode(ptr->_, SSL_SESS_CACHE_CLIENT);
	}
	return ptr;
}

void pgs_ssl_ctx_free(pgs_ssl_ctx_t *ctx)
{
	SSL_CTX_free(ctx->_);
	free(ctx);
}

pgs_ssl_t *pgs_ssl_new(pgs_ssl_ctx_t *ctx, void *hostname)
{
	pgs_ssl_t *ptr = malloc(sizeof(pgs_ssl_t));
	ptr->_ = NULL;
	if ((ptr->_ = SSL_new(ctx->_)))
		SSL_set_tlsext_host_name(ptr->_, hostname);

	return ptr;
}

void pgs_ssl_close(pgs_ssl_t *ssl)
{
	SSL_shutdown(ssl->_);
	SSL_clear(ssl->_);
	SSL_free(ssl->_);
	free(ssl);
}

// init bev with ssl context
// return 0 for ok
// return -1 for error
int pgs_session_outbound_ssl_bev_init(struct bufferevent **bev,
				      struct event_base *base,
				      pgs_ssl_ctx_t *ssl_ctx, const char *sni)
{
	pgs_ssl_t *ssl = pgs_ssl_new(ssl_ctx, (void *)sni);

	if (ssl == NULL) {
		return -1;
	}
	*bev = bufferevent_openssl_socket_new(
		base, -1, ssl->_, BUFFEREVENT_SSL_CONNECTING,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
#ifdef BUFFEREVENT_SSL_BATCH_WRITE
	bufferevent_ssl_set_flags(*bev, BUFFEREVENT_SSL_DIRTY_SHUTDOWN |
						BUFFEREVENT_SSL_BATCH_WRITE);
#else
	bufferevent_openssl_set_allow_dirty_shutdown(*bev, 1);
#endif
	return 0;
}

void pgs_free_bev_ssl_ctx(struct bufferevent *bev)
{
	SSL *ssl_ = bufferevent_openssl_get_ssl(bev);
	pgs_ssl_t *ssl = container_of(&ssl_, pgs_ssl_t, _);

	if (ssl)
		pgs_ssl_close(ssl);
}
