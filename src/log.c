#include "log.h"
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <stdarg.h>

static char *log_levels[] = { "DEBUG", "INFO", "WARN", "ERROR" };
static char *log_colors[] = { "\e[01;32m", "\e[01;32m", "\e[01;35m",
			      "\e[01;31m" };

pgs_logger_msg_t *pgs_logger_msg_new(char *msg, uint32_t tid)
{
	pgs_logger_msg_t *ptr = malloc(sizeof(pgs_logger_msg_t));
	ptr->msg = msg;
	ptr->tid = tid;
	return ptr;
}
void pgs_logger_msg_free(pgs_logger_msg_t *lmsg)
{
	free(lmsg->msg);
	free(lmsg);
}

void pgs_logger_debug_buffer(pgs_logger_t *logger, unsigned char *buf, int size)
{
	char hexbuf[2 * size + 1];
	for (int i = 0; i < size; i++) {
		sprintf(hexbuf + i * 2, "%02x", (int)buf[i]);
	}
	hexbuf[2 * size] = '\0';
	pgs_logger_debug(logger, "%s", hexbuf);
}

pgs_logger_t *pgs_logger_new(pgs_mpsc_t *mpsc, LOG_LEVEL level, bool isatty)
{
	pgs_logger_t *ptr = malloc(sizeof(pgs_logger_t));
	ptr->level = level;
	ptr->mpsc = mpsc;
	ptr->tid = (uint32_t)pthread_self();
	ptr->isatty = isatty;
	return ptr;
}

void pgs_logger_free(pgs_logger_t *logger)
{
	free(logger);
}

void pgs_logger_log(LOG_LEVEL level, pgs_logger_t *logger, const char *fmt, ...)
{
	if (level < logger->level) {
		return;
	}

	va_list args;
	// construct string, then send to mpsc
	// LEVEL date-time tid: MSG
	char msg[MAX_MSG_LEN];
	char datetime[20];
	PARSE_TIME_NOW(datetime);
	va_start(args, fmt);
	int size = vsnprintf(msg, MAX_MSG_LEN - 1, fmt, args);
	va_end(args);

	if (size <= 0)
		return;

	char *m = malloc(sizeof(char) * (size + 64));

	if (logger->isatty) {
		sprintf(m, "%s%s [thread-%04d] %s: \e[0m%s",
			log_colors[level] /*10*/, datetime /*20*/,
			(int)(logger->tid % 10000), log_levels[level], msg);

	} else {
		sprintf(m, "%s [thread-%04d] %s: %s", datetime,
			(int)(logger->tid % 10000), log_levels[level], msg);
	}
	pgs_logger_msg_t *_msg = pgs_logger_msg_new(m, logger->tid);

	pgs_mpsc_send(logger->mpsc, _msg);
}

// directly send to log file
// called from main thread
void pgs_logger_main_log(LOG_LEVEL level, FILE *output, const char *fmt, ...)
{
	va_list args;
	// LEVEL date-time: MSG
	char msg[MAX_MSG_LEN - 32];
	char datetime[32];
	PARSE_TIME_NOW(datetime);
	va_start(args, fmt);
	vsprintf(msg, fmt, args);
	va_end(args);

	if (isatty(fileno(output))) {
		fprintf(output, "%s%s [thread-main] %s: \e[0m%s\n",
			log_colors[level], datetime, log_levels[level], msg);
	} else {
		fprintf(output, "%s [thread-main] %s: %s\n", datetime,
			log_levels[level], msg);
	}

	fflush(output);
}

void pgs_logger_tryrecv(pgs_logger_t *logger, FILE *output)
{
	while (true) {
		pgs_logger_msg_t *msg = pgs_mpsc_recv(logger->mpsc);
		if (msg != NULL) {
			fprintf(output, "%s\n", msg->msg);
			fflush(output);
			pgs_logger_msg_free(msg);
		} else {
			return;
		}
	}
}
