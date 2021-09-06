#ifndef _PGS_SSL
#define _PGS_SSL

#ifdef USE_MBEDTLS
#include <mbedtls/ssl.h>
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include <mbedtls/error.h>
typedef struct pgs_ssl_ctx_s {
	mbedtls_ssl_config conf;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
} pgs_ssl_ctx_t;

typedef mbedtls_ssl_context pgs_ssl_t;
#else

#include <openssl/ssl.h>
#include <openssl/err.h>
typedef SSL pgs_ssl_t;
typedef SSL_CTX pgs_ssl_ctx_t;

#endif // USE_MBEDTLS

#include <event2/bufferevent_ssl.h>

static pgs_ssl_ctx_t *pgs_ssl_ctx_new();
static void pgs_ssl_ctx_free(pgs_ssl_ctx_t *ctx);
static pgs_ssl_t *pgs_ssl_new(pgs_ssl_ctx_t *ctx, void *hostname);
static void pgs_ssl_close(pgs_ssl_t *ssl);
static inline int pgs_session_outbound_ssl_bev_init(struct bufferevent **bev,
						    struct event_base *base,
						    pgs_ssl_ctx_t *ssl_ctx,
						    const char *sni);
static inline void pgs_free_bev_ssl_ctx(struct bufferevent *bev);

#ifdef USE_MBEDTLS

static pgs_ssl_ctx_t *pgs_ssl_ctx_new()
{
	pgs_ssl_ctx_t *ctx = malloc(sizeof(pgs_ssl_ctx_t));

	mbedtls_ssl_config_init(&ctx->conf);
	mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
	mbedtls_entropy_init(&ctx->entropy);

	if (mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func,
				  &ctx->entropy, NULL, 0)) {
		goto error;
	}

	if (mbedtls_ssl_config_defaults(&ctx->conf, MBEDTLS_SSL_IS_CLIENT,
					MBEDTLS_SSL_TRANSPORT_STREAM,
					MBEDTLS_SSL_PRESET_DEFAULT)) {
		goto error;
	}

	mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_NONE);

	mbedtls_ssl_conf_rng(&ctx->conf, mbedtls_ctr_drbg_random,
			     &ctx->ctr_drbg);

	return ctx;

error:
	pgs_ssl_ctx_free(ctx);
	return NULL;
}

static void pgs_ssl_ctx_free(pgs_ssl_ctx_t *ctx)
{
	mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
	mbedtls_entropy_free(&ctx->entropy);
	mbedtls_ssl_config_free(&ctx->conf);
	free(ctx);
}

static pgs_ssl_t *pgs_ssl_new(pgs_ssl_ctx_t *ctx, void *hostname)
{
	pgs_ssl_t *ssl = malloc(sizeof(pgs_ssl_t));
	int ret;
	mbedtls_ssl_init(ssl);

	if ((ret = mbedtls_ssl_setup(ssl, &ctx->conf)) != 0) {
		goto error;
	}
	if ((ret = mbedtls_ssl_set_hostname(ssl, hostname)) != 0) {
		goto error;
	}

	return ssl;
error:
	pgs_ssl_close(ssl);
	return NULL;
}

static void pgs_ssl_close(pgs_ssl_t *ssl)
{
	mbedtls_ssl_free(ssl);
	free(ssl);
}

static inline int pgs_session_outbound_ssl_bev_init(struct bufferevent **bev,
						    struct event_base *base,
						    pgs_ssl_ctx_t *ssl_ctx,
						    const char *sni)
{
	pgs_ssl_t *ssl = pgs_ssl_new(ssl_ctx, (void *)sni);

	if (ssl == NULL) {
		return -1;
	}
	*bev = bufferevent_mbedtls_socket_new(
		base, -1, ssl, BUFFEREVENT_SSL_CONNECTING,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	bufferevent_mbedtls_set_allow_dirty_shutdown(*bev, 1);

	return 0;
}

static inline void pgs_free_bev_ssl_ctx(struct bufferevent *bev)
{
	pgs_ssl_t *ssl = bufferevent_mbedtls_get_ssl(bev);
	if (ssl)
		pgs_ssl_close(ssl);
}

#else

// default to openssl
static pgs_ssl_ctx_t *pgs_ssl_ctx_new()
{
	pgs_ssl_ctx_t *ctx = NULL;

	OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
				 OPENSSL_INIT_LOAD_CRYPTO_STRINGS,
			 NULL);
	if ((ctx = SSL_CTX_new(SSLv23_client_method()))) {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
		SSL_CTX_set_verify_depth(ctx, 0);
		SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
		SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);
	}
	return ctx;
}

static void pgs_ssl_ctx_free(pgs_ssl_ctx_t *ctx)
{
	SSL_CTX_free(ctx);
}

static pgs_ssl_t *pgs_ssl_new(pgs_ssl_ctx_t *ctx, void *hostname)
{
	pgs_ssl_t *ssl = NULL;
	if ((ssl = SSL_new(ctx)))
		SSL_set_tlsext_host_name(ssl, hostname);

	return ssl;
}

static void pgs_ssl_close(pgs_ssl_t *ssl)
{
	SSL_shutdown(ssl);
	SSL_clear(ssl);
}

// init bev with ssl context
// return 0 for ok
// return -1 for error
static inline int pgs_session_outbound_ssl_bev_init(struct bufferevent **bev,
						    struct event_base *base,
						    pgs_ssl_ctx_t *ssl_ctx,
						    const char *sni)
{
	pgs_ssl_t *ssl = pgs_ssl_new(ssl_ctx, (void *)sni);

	if (ssl == NULL) {
		return -1;
	}
	*bev = bufferevent_openssl_socket_new(
		base, -1, ssl, BUFFEREVENT_SSL_CONNECTING,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	bufferevent_openssl_set_allow_dirty_shutdown(*bev, 1);

	return 0;
}

static inline void pgs_free_bev_ssl_ctx(struct bufferevent *bev)
{
	pgs_ssl_t *ssl = bufferevent_openssl_get_ssl(bev);
	if (ssl)
		pgs_ssl_close(ssl);
}

#endif // PGS_USE_MBEDTLS

#endif
