#include "pgs_core.h"

SSL_CTX *pgs_ssl_ctx_new()
{
	SSL_CTX *ctx = NULL;

	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	if ((ctx = SSL_CTX_new(SSLv23_client_method()))) {
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
		SSL_CTX_set_verify_depth(ctx, 0);
		SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
		SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);
	}

	return ctx;
}

SSL *pgs_ssl_new(SSL_CTX *ctx, void *hostname)
{
	SSL *ssl = NULL;
	if ((ssl = SSL_new(ctx)))
		SSL_set_tlsext_host_name(ssl, hostname);

	return ssl;
}

void pgs_ssl_close(SSL *ssl)
{
	SSL_shutdown(ssl);
	SSL_clear(ssl);
}
