#include "defs.h"
#include "ssl.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>
#include <stdio.h>

typedef struct pgs_ssl_sessions_cache_s {
	const char *sni;
	pgs_list_t *ssl_sessions;
	pthread_mutex_t lock;
} pgs_ssl_sessions_cache_t;

static pgs_ssl_sessions_cache_t *session_cache_new(const char *sni);
static void session_cache_free(pgs_ssl_sessions_cache_t *);

static int new_session_cb(SSL *ssl, SSL_SESSION *session);
static void remove_session_cb(SSL_CTX *_, SSL_SESSION *session);

static SSL_SESSION *get_session_from_cache(const char *sni);

// each server per cache
pgs_list_t *SESSION_CACHE_LIST = NULL;

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
					// TODO: we should call custom validate function to validate hostname
				}
			}
		}
		SSL_CTX_set_mode(ptr->_, SSL_MODE_AUTO_RETRY);
		if (SESSION_CACHE_LIST == NULL) {
			SESSION_CACHE_LIST = pgs_list_new();
			SESSION_CACHE_LIST->free = (void *)session_cache_free;

			for (int i = 0; i < config->servers_count; ++i) {
				pgs_server_config_t sconfig =
					config->servers[i];
				pgs_ssl_sessions_cache_t *cache = NULL;
				if (IS_TROJAN_SERVER(sconfig.server_type)) {
					const char *sni = NULL;
					GET_TROJAN_SNI(&sconfig, sni);
					cache = session_cache_new(sni);
				} else if (IS_V2RAY_SERVER(
						   sconfig.server_type)) {
					pgs_config_extra_v2ray_t *vconf =
						(pgs_config_extra_v2ray_t *)
							sconfig.extra;
					if (vconf->ssl.enabled) {
						const char *sni = NULL;
						GET_V2RAY_SNI(&sconfig, sni);
						cache = session_cache_new(sni);
					}
				}
				if (cache != NULL) {
					pgs_list_add(SESSION_CACHE_LIST,
						     pgs_list_node_new(cache));
				}
			}
		}
		SSL_CTX_set_session_cache_mode(ptr->_, SSL_SESS_CACHE_CLIENT);
		SSL_CTX_set_options(ptr->_, SSL_OP_NO_TICKET);
		SSL_CTX_sess_set_new_cb(ptr->_, new_session_cb);
		SSL_CTX_sess_set_remove_cb(ptr->_, remove_session_cb);
	}
	return ptr;
}

void pgs_ssl_ctx_free(pgs_ssl_ctx_t *ctx)
{
	SSL_CTX_free(ctx->_);
	free(ctx);
	if (SESSION_CACHE_LIST != NULL) {
		pgs_list_free(SESSION_CACHE_LIST);
		SESSION_CACHE_LIST = NULL;
	}
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
	SSL_SESSION *session = get_session_from_cache(sni);
	if (session != NULL) {
		SSL_set_session(ssl, session);
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

// =====================================================
static int new_session_cb(SSL *ssl, SSL_SESSION *session)
{
	if (SESSION_CACHE_LIST == NULL)
		return 0;
	const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (sni != NULL) {
		pgs_list_node_t *cur = NULL, *next = NULL;
		pgs_ssl_sessions_cache_t *cache = NULL;
		pgs_list_foreach(SESSION_CACHE_LIST, cur, next)
		{
			cache = (pgs_ssl_sessions_cache_t *)(cur->val);
			if (strcmp(cache->sni, sni) == 0) {
				break;
			}
		}
		if (cache != NULL) {
			pthread_mutex_lock(&cache->lock);
			pgs_list_add(cache->ssl_sessions,
				     pgs_list_node_new(session));
			pthread_mutex_unlock(&cache->lock);
		}
	}

	return 0;
}

static void remove_session_cb(SSL_CTX *_, SSL_SESSION *session)
{
	if (SESSION_CACHE_LIST == NULL)
		return;

	pgs_list_node_t *cur = NULL, *next = NULL;
	pgs_ssl_sessions_cache_t *cache = NULL;
	bool found = false;
	pgs_list_foreach(SESSION_CACHE_LIST, cur, next)
	{
		cache = (pgs_ssl_sessions_cache_t *)(cur->val);

		pgs_list_node_t *scur = NULL, *snext = NULL;
		pgs_list_foreach(cache->ssl_sessions, scur, snext)
		{
			if (scur->val == session) {
				found = true;
				break;
			}
		}
		if (found) {
			break;
		}
	}

	if (cache != NULL && found) {
		pthread_mutex_lock(&cache->lock);
		pgs_list_del_val(cache->ssl_sessions, session);
		pthread_mutex_unlock(&cache->lock);
	}
}

static pgs_ssl_sessions_cache_t *session_cache_new(const char *sni)
{
	pgs_ssl_sessions_cache_t *ptr =
		malloc(sizeof(pgs_ssl_sessions_cache_t));
	ptr->ssl_sessions = pgs_list_new();
	if (pthread_mutex_init(&ptr->lock, NULL) != 0) {
		goto error;
	}

	ptr->sni = sni;

	return ptr;
error:
	session_cache_free(ptr);
	return NULL;
}

static void session_cache_free(pgs_ssl_sessions_cache_t *ptr)
{
	if (ptr != NULL) {
		pthread_mutex_destroy(&ptr->lock);
		pgs_list_free(ptr->ssl_sessions);
		free(ptr);
		ptr = NULL;
	}
}

static SSL_SESSION *get_session_from_cache(const char *sni)
{
	SSL_SESSION *session = NULL;
	if (SESSION_CACHE_LIST == NULL)
		return NULL;
	if (sni == NULL)
		return NULL;
	pgs_list_node_t *cur = NULL, *next = NULL;
	pgs_ssl_sessions_cache_t *cache = NULL;
	pgs_list_foreach(SESSION_CACHE_LIST, cur, next)
	{
		cache = (pgs_ssl_sessions_cache_t *)(cur->val);
		if (strcmp(cache->sni, sni) == 0) {
			break;
		}
	}
	if (cache != NULL) {
		pthread_mutex_lock(&cache->lock);
		if (cache->ssl_sessions->len > 0) {
			session = cache->ssl_sessions->head->val;
		}
		pthread_mutex_unlock(&cache->lock);
	}
	return session;
}
