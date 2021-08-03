#ifndef _PGS_CORE
#define _PGS_CORE

#include <openssl/ssl.h>
#include <openssl/err.h>

static SSL_CTX *pgs_ssl_ctx_new()
{
	SSL_CTX *ctx = NULL;

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

static SSL *pgs_ssl_new(SSL_CTX *ctx, void *hostname)
{
	SSL *ssl = NULL;
	if ((ssl = SSL_new(ctx)))
		SSL_set_tlsext_host_name(ssl, hostname);

	return ssl;
}

static void pgs_ssl_close(SSL *ssl)
{
	SSL_shutdown(ssl);
	SSL_clear(ssl);
}

#endif
