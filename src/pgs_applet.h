#ifndef _PGS_APPLET
#define _PGS_APPLET

#include "pgs_core.h"
#include "pgs_server_manager.h"
#include "pgs_log.h"

typedef struct pgs_tray_context_s pgs_tray_context_t;

struct pgs_tray_context_s {
	pgs_logger_t *logger;
	pgs_server_manager_t *sm;
	pthread_t *threads;
	int thread_num;
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
#define TRAY_ICON1 "icon.svg"
#define TRAY_ICON2 "icon.svg"
#elif TRAY_APPKIT
#define TRAY_ICON1 "icon.png"
#define TRAY_ICON2 "icon.png"
#elif TRAY_WINAPI
#define TRAY_ICON1 "icon.ico"
#define TRAY_ICON2 "icon.ico"
#endif

typedef struct tray pgs_tray_t;
typedef struct tray_menu pgs_tray_menu_t;

void pgs_tray_init(pgs_tray_context_t *ctx);
void pgs_tray_clean();

#endif

void pgs_tran_start(pgs_tray_context_t *ctx);

#endif
