#ifndef _PGS_APPLET_H
#define _PGS_APPLET_H

#include <pthread.h>

#include "server/manager.h"
#include "server/local.h"
#include "log.h"
#ifndef _WIN32
#include <unistd.h>
#endif

typedef struct pgs_tray_context_s {
	pgs_logger_t *logger;
	pgs_server_manager_t *sm;
	char *metrics_label;

	void (*quit)();
} pgs_tray_context_t;

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
void pgs_tray_update();
#endif

void pgs_tray_start(pgs_tray_context_t *ctx);

#endif
