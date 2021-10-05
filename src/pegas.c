#include "pegas.h"
#include "config.h"
#include "acl.h"
#include "mpsc.h"
#include "defs.h"
#include "ssl.h"

#ifdef WITH_APPLET
#include "applet.h"
#endif

#include "server/manager.h"
#include "server/helper.h"
#include "server/local.h"

#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/un.h>
#include <netinet/in.h>

static pgs_config_t *CONFIG = NULL;
static pgs_acl_t *ACL = NULL;
static pgs_mpsc_t *MPSC = NULL;
static pgs_logger_t *LOGGER = NULL; /* log consumer */
static pgs_server_manager_t *SM = NULL;
static pgs_ssl_ctx_t *SSL_CTX = NULL;

static pthread_t *THREADS = NULL;
static pgs_local_server_t **LOCAL_SERVERS = NULL; /* array of const points */

static pthread_t HELPER_THREAD = 0;

static pgs_helper_thread_t *HELPER_THREAD_CTX = NULL; /* const pointer */

static int lfd = 0;
static int cfd = 0;
static int snum = 0;

static bool RUNNING = false;
static bool SHUTINGDOWN = false;

static bool pgs_init(const char *config, const char *acl, int threads);
static void pgs_clean();

static int init_local_server_fd(const pgs_config_t *config, int *fd,
				int sock_type);
static int init_control_fd(const pgs_config_t *config, int *fd);

static bool pgs_start_local_servers();
static bool pgs_start_helper();

bool pgs_start(const char *config, const char *acl, int threads,
	       void (*shutdown)())
{
	if (RUNNING)
		return false;

	if (!pgs_init(config, acl, threads))
		return false;

	if (!pgs_start_local_servers())
		return false;

	if (!pgs_start_helper())
		return false;

	assert(HELPER_THREAD != 0);

	RUNNING = true;

#ifdef WITH_APPLET
	pgs_tray_context_t tray_ctx = { LOGGER, SM, NULL, shutdown };
	pgs_tray_start(&tray_ctx);
#endif

	// will block here

	for (int i = 0; i < snum; i++) {
		pthread_join(THREADS[i], NULL);
	}

	pthread_join(HELPER_THREAD, NULL);

	// stoped by other threads

	RUNNING = false;

	// cleanup
	pgs_clean();

	return true;
}

void pgs_stop()
{
	if (SHUTINGDOWN)
		return;
	SHUTINGDOWN = true;

	if (LOCAL_SERVERS != NULL) {
		for (int i = 0; i < snum; i++) {
			if (LOCAL_SERVERS[i] != NULL) {
				// clean the thread resources
				evuser_trigger(LOCAL_SERVERS[i]->ev_term);
			}
		}
	}

	if (HELPER_THREAD_CTX != NULL) {
		evuser_trigger(HELPER_THREAD_CTX->ev_term);
	}

	SHUTINGDOWN = false;
}

void pgs_get_servers(char *out, int max_len, int *olen)
{
	pgs_sm_get_servers(SM, out, max_len, olen);
}

bool pgs_set_server(int idx)
{
	return pgs_sm_set_server(SM, idx);
}

// ======================== static functions
static int init_local_server_fd(const pgs_config_t *config, int *fd,
				int sock_type)
{
	int err = 0;
	struct sockaddr_in sin = { 0 };
	int port = config->local_port;

	memset(&sin, 0, sizeof(sin));

	sin.sin_family = AF_INET;
	err = inet_pton(AF_INET, config->local_address, &sin.sin_addr);
	if (err <= 0) {
		if (err == 0)
			pgs_config_error(config, "Not in presentation format");
		else
			perror("inet_pton");
		exit(EXIT_FAILURE);
	}
	sin.sin_port = htons(port);

	*fd = socket(AF_INET, sock_type, 0);
	int reuse_port = 1;

	err = setsockopt(*fd, SOL_SOCKET, SO_REUSEPORT,
			 (const void *)&reuse_port, sizeof(int));
	if (err < 0) {
		perror("setsockopt");
		return err;
	}

	int flag = fcntl(*fd, F_GETFL, 0);
	fcntl(*fd, F_SETFL, flag | O_NONBLOCK);

	err = bind(*fd, (struct sockaddr *)&sin, sizeof(sin));

	if (err < 0) {
		perror("bind");
		return err;
	}
	return err;
}

static int init_control_fd(const pgs_config_t *config, int *fd)
{
	int err = 0;
	if (config->control_port) {
		// tcp port
		struct sockaddr_in sin;
		int port = config->control_port;

		memset(&sin, 0, sizeof(sin));

		sin.sin_family = AF_INET;
		err = inet_pton(AF_INET, config->local_address, &sin.sin_addr);
		if (err <= 0) {
			if (err == 0)
				pgs_config_error(config,
						 "Not in presentation format");
			else
				perror("inet_pton");
			exit(EXIT_FAILURE);
		}
		sin.sin_port = htons(port);

		*fd = socket(AF_INET, SOCK_STREAM, 0);
		int flag = fcntl(*fd, F_GETFL, 0);
		fcntl(*fd, F_SETFL, flag | O_NONBLOCK);
		err = bind(*fd, (struct sockaddr *)&sin, sizeof(sin));
		if (err < 0) {
			perror("bind");
			return err;
		}
	} else if (config->control_file) {
		// unix socket
		struct sockaddr_un server;
		*fd = socket(AF_UNIX, SOCK_STREAM, 0);
		server.sun_family = AF_UNIX;
		strcpy(server.sun_path, config->control_file);
		int flag = fcntl(*fd, F_GETFL, 0);
		fcntl(*fd, F_SETFL, flag | O_NONBLOCK);
		unlink(config->control_file);
		err = bind(*fd, (struct sockaddr *)&server,
			   sizeof(struct sockaddr_un));
		if (err < 0) {
			perror("bind");
			return err;
		}
	}

	return err;
}

static bool pgs_start_local_servers()
{
	THREADS = malloc(snum * sizeof(pthread_t));
	LOCAL_SERVERS = malloc(snum * sizeof(pgs_local_server_t *));
	for (int i = 0; i < snum; i++) {
		LOCAL_SERVERS[i] = NULL;
	}

	pthread_attr_t attr;
	pthread_attr_init(&attr);
	// pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	// Local server threads
	for (int i = 0; i < snum; i++) {
		// ctx is freed in worker threads
		pgs_local_server_ctx_t *ctx =
			malloc(sizeof(pgs_local_server_ctx_t));
		ctx->fd = lfd;
		ctx->mpsc = MPSC;
		ctx->config = CONFIG;
		ctx->sm = SM;
		ctx->acl = ACL;
		ctx->ssl_ctx = SSL_CTX;
		ctx->local_server_ref = (void **)&LOCAL_SERVERS[i];

		pthread_create(&THREADS[i], &attr, start_local_server, ctx);
	}
	pthread_attr_destroy(&attr);
	return true;
}

/*
 * Logger / metrics / control(rpc) / signal
 */
static bool pgs_start_helper()
{
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	pgs_helper_thread_ctx_t *ctx = malloc(sizeof(pgs_helper_thread_t));
	ctx->cfd = cfd;
	ctx->config = CONFIG;
	ctx->logger = LOGGER;
	ctx->sm = SM;
	ctx->ssl_ctx = SSL_CTX;
	ctx->helper_ref = (void **)&HELPER_THREAD_CTX;

	pthread_create(&HELPER_THREAD, &attr, pgs_helper_thread_start, ctx);

	pthread_attr_destroy(&attr);

	return true;
}

static bool pgs_init(const char *config, const char *acl, int threads)
{
	snum = threads;
	CONFIG = pgs_config_load(config);
	if (CONFIG == NULL) {
		return false;
	}

#ifdef WITH_ACL
	if (acl != NULL) {
		ACL = pgs_acl_new(acl);
		if (ACL == NULL) {
			return false;
		}
	}
#endif

	if (init_local_server_fd(CONFIG, &lfd, SOCK_STREAM) < 0) {
		return false;
	}
	if (init_control_fd(CONFIG, &cfd) < 0) {
		return false;
	}
	MPSC = pgs_mpsc_new(MAX_LOG_MPSC_SIZE);

	LOGGER = pgs_logger_new(MPSC, CONFIG->log_level, CONFIG->log_isatty);

	SM = pgs_server_manager_new(CONFIG->servers, CONFIG->servers_count);

	SSL_CTX = pgs_ssl_ctx_new();

	return true;
}

static void pgs_clean()
{
	if (LOCAL_SERVERS != NULL) {
		for (int i = 0; i < snum; i++) {
			if (LOCAL_SERVERS[i] != NULL) {
				LOCAL_SERVERS[i] = NULL;
			}
		}
		free(LOCAL_SERVERS);
		LOCAL_SERVERS = NULL;
	}

	if (THREADS != NULL) {
		free(THREADS);
		THREADS = NULL;
	}
	if (HELPER_THREAD_CTX != NULL) {
		HELPER_THREAD_CTX = NULL;
	}
	if (HELPER_THREAD != 0) {
		HELPER_THREAD = 0;
	}
	if (SSL_CTX != NULL) {
		pgs_ssl_ctx_free(SSL_CTX);
		SSL_CTX = NULL;
	}
	if (SM != NULL) {
		pgs_server_manager_free(SM);
		SM = NULL;
	}
	if (LOGGER != NULL) {
		pgs_logger_free(LOGGER);
		LOGGER = NULL;
	}
	if (MPSC != NULL) {
		pgs_mpsc_free(MPSC);
		MPSC = NULL;
	}

	if (CONFIG != NULL) {
		pgs_config_free(CONFIG);
		CONFIG = NULL;
	}
#ifdef WITH_ACL
	if (ACL != NULL) {
		pgs_acl_free(ACL);
		ACL = NULL;
	}
#endif

	// will be closed by bufferevents
	lfd = 0;
	cfd = 0;

	snum = 0;
}
