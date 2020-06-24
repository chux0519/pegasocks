#ifndef _PGS_LOG
#define _PGS_LOG

#include "pgs_mpsc.h"
#include "stdio.h"

typedef struct pgs_logger_s pgs_logger_t;
typedef enum { DEBUG, INFO, WARN, ERROR } LOG_LEVEL;
typedef struct pgs_logger_msg_s pgs_logger_msg_t;
typedef struct pgs_logger_server_s pgs_logger_server_t;

#define MAX_MSG_LEN 4096
#define TIME_FORMAT "%Y-%m-%d %H:%M:%S"
#define pgs_logger_debug(logger, ...) pgs_logger_log(DEBUG, logger, __VA_ARGS__)
#define pgs_logger_info(logger, ...) pgs_logger_log(INFO, logger, __VA_ARGS__)
#define pgs_logger_warn(logger, ...) pgs_logger_log(WARN, logger, __VA_ARGS__)
#define pgs_logger_error(logger, ...) pgs_logger_log(ERROR, logger, __VA_ARGS__)
#define pgs_logger_main_info(fp, ...) pgs_logger_main_log(INFO, fp, __VA_ARGS__)
#define pgs_logger_main_bug(fp, ...) pgs_logger_main_log(DEBUG, fp, __VA_ARGS__)
#define pgs_logger_main_error(fp, ...)                                         \
	pgs_logger_main_log(ERROR, fp, __VA_ARGS__)

void pgs_logger_debug_buffer(pgs_logger_t *logger, unsigned char *buf,
			     int size);

struct pgs_logger_s {
	pgs_mpsc_t *mpsc;
	LOG_LEVEL level;
	pgs_tid tid;
	bool isatty;
};

struct pgs_logger_msg_s {
	char *msg;
	pgs_tid tid;
};

struct pgs_logger_server_s {
	pgs_logger_t *logger;
	FILE *output;
};

pgs_logger_t *pgs_logger_new(pgs_mpsc_t *mpsc, LOG_LEVEL level, bool isatty);
void pgs_logger_free(pgs_logger_t *logger);

// for client, construct and send string to mpsc
void pgs_logger_log(LOG_LEVEL level, pgs_logger_t *logger, const char *fmt,
		    ...);

// for main thread
void pgs_logger_main_log(LOG_LEVEL level, FILE *output, const char *fmt, ...);

// logger thread functions
pgs_logger_server_t *pgs_logger_server_new(pgs_logger_t *logger, FILE *output);
void pgs_logger_server_free(pgs_logger_server_t *server);
void pgs_logger_server_serve(pgs_logger_server_t *server);

pgs_logger_msg_t *pgs_logger_msg_new(char *msg, pgs_tid tid);
void pgs_logger_msg_free(pgs_logger_msg_t *lmsg);

// start point, will run in a seperate thread
void *start_logger(void *ctx);

#endif
