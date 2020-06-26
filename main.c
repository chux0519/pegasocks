#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include "pgs_local_server.h"
#include "pgs_config.h"
#include "pgs_server_manager.h"

#define MAX_SERVER_THREADS 4
#define MAX_LOG_MPSC_SIZE 64

int main(int argc, char **argv)
{
	// default settings
	int server_threads = MAX_SERVER_THREADS;
	char default_config_path[] = "config.json";
	char *config_path = default_config_path;

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
	// logger for logger server
	pgs_logger_t *logger =
		pgs_logger_new(mpsc, config->log_level, config->log_isatty);

	pgs_server_manager_t *sm =
		pgs_server_manager_new(config->servers, config->servers_count);

	pgs_local_server_ctx_t ctx = { server_fd, mpsc, config, sm };

	pgs_logger_server_t *logger_server =
		pgs_logger_server_new(logger, config->log_file);

	// Spawn threads
	pthread_t threads[server_threads + 1];
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	// Start logger thread
	pthread_create(&threads[0], &attr, start_logger, logger_server);

	// Local server threads
	for (int i = 1; i <= server_threads; i++) {
		pthread_create(&threads[i], &attr, start_local_server,
			       (void *)&ctx);
	}

	// block on all threads
	for (int i = 0; i <= server_threads; i++) {
		pthread_join(threads[i], NULL);
	}

	pthread_attr_destroy(&attr);

	pgs_logger_server_free(logger_server);
	pgs_logger_free(logger);
	pgs_mpsc_free(mpsc);
	pgs_config_free(config);

	return 0;
}
