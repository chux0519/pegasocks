#ifndef _PGS_APPLET
#define _PGS_APPLET

#include <pthread.h>
#include "pgs_server_manager.h"
#include "pgs_log.h"
#include "pgs_local_server.h"

typedef struct pgs_tray_context_s pgs_tray_context_t;

typedef void(spawn_fn)(pthread_t *threads, int server_threads,
		       pgs_local_server_ctx_t *ctx);

typedef void(shutdown_fn)(pthread_t *threads, int server_threads);

struct pgs_tray_context_s {
	pgs_logger_t *logger;
	pgs_server_manager_t *sm;
	pthread_t *threads;
	int thread_num;
	spawn_fn *spawn_workers;
	shutdown_fn *kill_workers;
	char *metrics_label;
};

#ifdef WITH_APPLET
#if defined(_WIN32) || defined(_WIN64)
#define TRAY_WINAPI 1
#elif defined(__linux__) || defined(linux) || defined(__linux)
#define TRAY_APPINDICATOR 1
#elif defined(__APPLE__) || defined(__MACH__)
#define TRAY_APPKIT 1
#endif
#include "tray/tray.h"

#if TRAY_APPINDICATOR
#define TRAY_ICON "icon.svg"
#elif TRAY_APPKIT
#define TRAY_ICON "icon.png"
#elif TRAY_WINAPI
#define TRAY_ICON "icon.ico"
#endif

typedef struct tray pgs_tray_t;
typedef struct tray_menu pgs_tray_menu_t;

void pgs_tray_init(pgs_tray_context_t *ctx);
void pgs_tray_clean();

#endif

void pgs_tray_start(pgs_tray_context_t *ctx);

#endif
