#include "defs.h"
#include "ssl.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>

struct pgs_ssl_ctx_s {
	SSL_CTX *_;
};

// default to openssl
pgs_ssl_ctx_t *pgs_ssl_ctx_new(pgs_config_t *config)
{
	pgs_ssl_ctx_t *ptr = malloc(sizeof(pgs_ssl_ctx_t));
	ptr->_ = NULL;

	OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
				 OPENSSL_INIT_LOAD_CRYPTO_STRINGS,
			 NULL);
	if ((ptr->_ = SSL_CTX_new(SSLv23_client_method()))) {
		if (!config->ssl_verify) {
			SSL_CTX_set_verify(ptr->_, SSL_VERIFY_NONE, NULL);
		} else {
			// Note: this will not verify the hostname, check: https://archives.seul.org/libevent/users/Jan-2013/msg00039.html
			SSL_CTX_set_verify(ptr->_, SSL_VERIFY_PEER, NULL);

			bool cert_loaded = false;

			// try load from crt
			if (config->ssl_crt != NULL) {
				if (SSL_CTX_load_verify_locations(
					    ptr->_, config->ssl_crt, NULL) !=
				    1) {
					pgs_config_error(
						config,
						"Failed to load cert: %s",
						config->ssl_crt);
				} else {
					pgs_config_info(config,
							"cert: %s loaded",
							config->ssl_crt);
					cert_loaded = true;
				}
			}
			// try load from system
			if (!cert_loaded) {
				X509_STORE *store =
					SSL_CTX_get_cert_store(ptr->_);
				if (X509_STORE_set_default_paths(store) != 1) {
					pgs_config_warn(
						config,
						"Failed to load system default cert, set verify mode to SSL_VERIFY_NONE now.");
					SSL_CTX_set_verify(
						ptr->_, SSL_VERIFY_NONE, NULL);
				} else {
					pgs_config_info(config,
							"system cert loaded");
				}
			}
		}
		SSL_CTX_set_mode(ptr->_, SSL_MODE_AUTO_RETRY);
		SSL_CTX_set_session_cache_mode(ptr->_, SSL_SESS_CACHE_OFF);
	}
	return ptr;
}

void pgs_ssl_ctx_free(pgs_ssl_ctx_t *ctx)
{
	SSL_CTX_free(ctx->_);
	free(ctx);
}

// init bev with ssl context
// return 0 for ok
// return -1 for error
int pgs_session_outbound_ssl_bev_init(struct bufferevent **bev, int fd,
				      struct event_base *base,
				      pgs_ssl_ctx_t *ssl_ctx, const char *sni)
{
	SSL *ssl = NULL;
	// ssl will be freed because BEV_OPT_CLOSE_ON_FREE
	if ((ssl = SSL_new(ssl_ctx->_)))
		SSL_set_tlsext_host_name(ssl, sni);

	if (ssl == NULL) {
		return -1;
	}
	*bev = bufferevent_openssl_socket_new(
		base, fd, ssl, BUFFEREVENT_SSL_CONNECTING,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
#ifdef BUFFEREVENT_SSL_BATCH_WRITE
	bufferevent_ssl_set_flags(*bev, BUFFEREVENT_SSL_DIRTY_SHUTDOWN |
						BUFFEREVENT_SSL_BATCH_WRITE);
#else
	bufferevent_openssl_set_allow_dirty_shutdown(*bev, 1);
#endif
	return 0;
}
