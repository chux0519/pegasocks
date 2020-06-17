#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include "crm_local_server.h"

#define MAX_SERVER_THREADS 4

int main(int argc, char **argv)
{
	int err = 0;
	struct sockaddr_in sin;

	int port = 8080;

	if (argc > 1)
		port = atoi(argv[1]);

	memset(&sin, 0, sizeof(sin));

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0); // 0.0.0.0
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

	pthread_t threads[MAX_SERVER_THREADS + 1];
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	// mpsc with 64 message slots
	crm_mpsc_t *mpsc = crm_mpsc_new(64);
	// logger for logger server
	crm_logger_t *logger = crm_logger_new(mpsc, DEBUG);

	crm_local_server_ctx_t ctx = { server_fd, mpsc };

	// Start logger thread
	pthread_create(&threads[0], &attr, start_logger, logger);

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
