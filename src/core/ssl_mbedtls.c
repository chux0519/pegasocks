#include "core/defs.h"
#include "core/ssl.h"

#include <mbedtls/ssl.h>
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include <mbedtls/error.h>

#include <stdlib.h>

struct pgs_ssl_ctx_s {
	mbedtls_ssl_config conf;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
};

struct pgs_ssl_s {
	mbedtls_ssl_context _;
};

pgs_ssl_ctx_t *pgs_ssl_ctx_new()
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

void pgs_ssl_ctx_free(pgs_ssl_ctx_t *ctx)
{
	mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
	mbedtls_entropy_free(&ctx->entropy);
	mbedtls_ssl_config_free(&ctx->conf);
	free(ctx);
}

pgs_ssl_t *pgs_ssl_new(pgs_ssl_ctx_t *ctx, void *hostname)
{
	pgs_ssl_t *ssl = malloc(sizeof(pgs_ssl_t));
	int ret;
	mbedtls_ssl_init(&ssl->_);

	if ((ret = mbedtls_ssl_setup(&ssl->_, &ctx->conf)) != 0) {
		goto error;
	}
	if ((ret = mbedtls_ssl_set_hostname(&ssl->_, hostname)) != 0) {
		goto error;
	}

	return ssl;
error:
	pgs_ssl_close(ssl);
	return NULL;
}

void pgs_ssl_close(pgs_ssl_t *ssl)
{
	mbedtls_ssl_free(&ssl->_);
	free(ssl);
}

int pgs_session_outbound_ssl_bev_init(struct bufferevent **bev,
				      struct event_base *base,
				      pgs_ssl_ctx_t *ssl_ctx, const char *sni)
{
	pgs_ssl_t *ssl = pgs_ssl_new(ssl_ctx, (void *)sni);

	if (ssl == NULL) {
		return -1;
	}
	*bev = bufferevent_mbedtls_socket_new(
		base, -1, &ssl->_, BUFFEREVENT_SSL_CONNECTING,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
#ifdef BUFFEREVENT_SSL_BATCH_WRITE
	bufferevent_ssl_set_flags(*bev, BUFFEREVENT_SSL_DIRTY_SHUTDOWN |
						BUFFEREVENT_SSL_BATCH_WRITE);
#else
	bufferevent_mbedtls_set_allow_dirty_shutdown(*bev, 1);
#endif

	return 0;
}

void pgs_free_bev_ssl_ctx(struct bufferevent *bev)
{
	mbedtls_ssl_context *ssl_ = bufferevent_mbedtls_get_ssl(bev);
	pgs_ssl_t *ssl = container_of(ssl_, pgs_ssl_t, _);

	if (ssl)
		pgs_ssl_close(ssl);
}
