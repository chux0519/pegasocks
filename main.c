#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include "crm_local_server.h"
#include "crm_config.h"

#define MAX_SERVER_THREADS 4
#define MAX_LOG_MPSC_SIZE 64

int main(int argc, char **argv)
{
	int err = 0;
	struct sockaddr_in sin;

	// load config
	crm_config_t *config = crm_config_load("config.json");
	if (config == NULL) {
		perror("invalid config");
		return -1;
	}

	printf("Starting Server at %s:%d\n", config->local_address,
	       config->local_port);

	int port = config->local_port;

	if (argc > 1)
		port = atoi(argv[1]);

	memset(&sin, 0, sizeof(sin));

	sin.sin_family = AF_INET;
	err = inet_pton(AF_INET, config->local_address, &sin.sin_addr);
	if (err <= 0) {
		if (err == 0)
			fprintf(stderr, "Not in presentation format");
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
	crm_mpsc_t *mpsc = crm_mpsc_new(MAX_LOG_MPSC_SIZE);
	// logger for logger server
	crm_logger_t *logger = crm_logger_new(mpsc, config->log_level);

	crm_local_server_ctx_t ctx = { server_fd, mpsc };

	crm_logger_server_t *logger_server =
		crm_logger_server_new(logger, config->log_file);

	// Spawn threads
	pthread_t threads[MAX_SERVER_THREADS + 1];
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	// Start logger thread
	pthread_create(&threads[0], &attr, start_logger, logger_server);

	// Local server threads
	for (int i = 1; i <= MAX_SERVER_THREADS; i++) {
		pthread_create(&threads[i], &attr, start_local_server,
			       (void *)&ctx);
	}

	// block on all threads
	for (int i = 0; i <= MAX_SERVER_THREADS; i++) {
		pthread_join(threads[i], NULL);
	}

	pthread_attr_destroy(&attr);

	return 0;
}
