#include <arpa/inet.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include "crm_local_server.h"

#define MAX_THREADS 4

// Start new local server
// One Local Server Per Thread
void *start_local_server(void *server_fd)
{
	int sfd = *(int *)server_fd;
	crm_local_server_t *local = crm_local_server_new(sfd);

	// will block here
	crm_local_server_run(local);

	// Destroy here
	crm_local_server_destroy(local);

	return 0;
}

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

	pthread_t threads[MAX_THREADS];
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	for (int i = 0; i < MAX_THREADS; i++) {
		pthread_create(&threads[i], &attr, start_local_server,
			       (void *)&server_fd);
	}

	for (int i = 0; i < MAX_THREADS; i++) {
		pthread_join(threads[i], NULL);
	}

	pthread_attr_destroy(&attr);

	return 0;
}
