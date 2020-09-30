#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include "pgs_local_server.h"
#include "pgs_config.h"
#include "pgs_server_manager.h"
#include "pgs_helper_thread.h"
#include "pgs_applet.h"

#define MAX_LOG_MPSC_SIZE 64
#define MAX_STATS_MPSC_SIZE 64

static void spawn_workers(pthread_t *threads, int server_threads,
			  pgs_local_server_ctx_t *ctx)
{
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	// Local server threads
	for (int i = 0; i < server_threads; i++) {
		pthread_create(&threads[i], &attr, start_local_server,
			       (void *)ctx);
	}

	pthread_attr_destroy(&attr);
}

static void kill_workers(pthread_t *threads, int server_threads)
{
	for (int i = 0; i < server_threads; i++) {
		pthread_kill(threads[i], SIGINT);
	}
}

int main(int argc, char **argv)
{
	// default settings
	int server_threads = sysconf(_SC_NPROCESSORS_CONF);
	char *config_path = NULL;

	// parse opt
	int opt = 0;
	while ((opt = getopt(argc, argv, "c:t:")) != -1) {
		switch (opt) {
		case 'c':
			config_path = optarg;
			break;
		case 't':
			server_threads = atoi(optarg);
			break;
		}
	}

	char full_config_path[512] = { 0 };
	char config_home[512] = { 0 };
	if (!config_path) {
		const char *xdg_config_home = getenv("XDG_CONFIG_HOME");
		const char *home = getenv("HOME");
		if (!xdg_config_home || strlen(xdg_config_home) == 0) {
			sprintf(config_home, "%s/.config", home);
		} else {
			strcpy(config_home, xdg_config_home);
		}
		sprintf(full_config_path, "%s/.pegasrc", config_home);
		if (access(full_config_path, F_OK) == -1) {
			sprintf(full_config_path, "%s/pegas/config",
				config_home);
			if (access(full_config_path, F_OK) == -1) {
				fprintf(stderr, "config is required");
				return -1;
			}
		}
		config_path = full_config_path;
	}

	int err = 0;
	struct sockaddr_in sin;

	// load config
	pgs_config_t *config = pgs_config_load(config_path);
	if (config == NULL) {
		fprintf(stderr, "invalid config");
		return -1;
	}

	pgs_config_info(config, "worker threads: %d, config: %s",
			server_threads, config_path);

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

	int server_fd = socket(AF_INET, SOCK_STREAM, 0);
	int reuse_port = 1;

	err = setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT,
			 (const void *)&reuse_port, sizeof(int));
	if (err < 0) {
		perror("setsockopt");
		return err;
	}

	int flag = fcntl(server_fd, F_GETFL, 0);
	fcntl(server_fd, F_SETFL, flag | O_NONBLOCK);

	err = bind(server_fd, (struct sockaddr *)&sin, sizeof(sin));

	if (err < 0) {
		perror("bind");
		return err;
	}
	// mpsc with 64 message slots
	pgs_mpsc_t *mpsc = pgs_mpsc_new(MAX_LOG_MPSC_SIZE);
	pgs_mpsc_t *statsq = pgs_mpsc_new(MAX_STATS_MPSC_SIZE);
	// logger for logger server
	pgs_logger_t *logger =
		pgs_logger_new(mpsc, config->log_level, config->log_isatty);

	pgs_server_manager_t *sm = pgs_server_manager_new(
		statsq, config->servers, config->servers_count);

	pgs_local_server_ctx_t ctx = { server_fd, mpsc, config, sm };
	pgs_helper_thread_arg_t helper_thread_arg = { sm, logger, config };

	// Spawn threads
	pthread_t threads[server_threads + 1];
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	// Start helper thread
	pthread_create(&threads[0], &attr, pgs_helper_thread_start,
		       (void *)&helper_thread_arg);

	// Local server threads
	spawn_workers(threads + 1, server_threads, &ctx);

#ifdef WITH_APPLET
	pgs_tray_context_t tray_ctx = { logger,	       sm,
					threads + 1,   server_threads,
					spawn_workers, kill_workers,
					NULL };
	pgs_tray_start(&tray_ctx);
#endif

	// block on helper thread
	pthread_join(threads[0], NULL);

	pthread_attr_destroy(&attr);

	pgs_logger_free(logger);
	pgs_mpsc_free(mpsc);
	pgs_config_free(config);

	return 0;
}
