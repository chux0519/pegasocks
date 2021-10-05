#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include "pegas.h"

#ifndef PGS_VERSION
#define PGS_VERSION "v0.0.0-develop"
#endif

static bool should_exit = false;

static void shutdown(int signum)
{
	should_exit = true;
	pgs_stop();
}

static void restart(int signum)
{
	should_exit = false;
	pgs_stop();
}

int main(int argc, char **argv)
{
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, shutdown);
	signal(SIGUSR1, restart);

#ifdef DEBUG_EVENT
	event_enable_debug_logging(EVENT_DBG_ALL);
#endif

	// default settings
	int server_threads = 4;
	char *config_path = NULL;
	char *acl_path = NULL;

	// parse opt
	int opt = 0;
	while ((opt = getopt(argc, argv, "va:c:t:")) != -1) {
		switch (opt) {
		case 'v':
			printf("%s\n", PGS_VERSION);
			exit(0);
		case 'a':
			acl_path = optarg;
			break;
		case 'c':
			config_path = optarg;
			break;
		case 't':
			server_threads = atoi(optarg);
			break;
		}
	}

	// get config path
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

	while (!should_exit) {
		bool ok = pgs_start(
			config_path, acl_path, server_threads,
			shutdown /* used by applet, can be NULL when not use applet */);

		if (!ok)
			return -1;
	}

	return 0;
}
