#include "crm_log.h"
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <stdarg.h>

static char *log_levels[] = { "debug", "info", "warn", "error" };

crm_logger_msg_t *crm_logger_msg_new(char *msg, crm_tid tid)
{
	crm_logger_msg_t *ptr = crm_malloc(sizeof(crm_logger_msg_t));
	ptr->msg = msg;
	ptr->tid = tid;
	return ptr;
}
void crm_logger_msg_free(crm_logger_msg_t *lmsg)
{
	crm_free(lmsg->msg);
	crm_free(lmsg);
}

void crm_logger_debug_buffer(crm_logger_t *logger, unsigned char *buf, int size)
{
	char hexbuf[2 * size + 1];
	for (int i = 0; i < size; i++) {
		sprintf(hexbuf + i * 2, "%02x", (int)buf[i]);
	}
	hexbuf[2 * size] = '\0';
	crm_logger_debug(logger, "%s", hexbuf);
}

crm_logger_t *crm_logger_new(crm_mpsc_t *mpsc, LOG_LEVEL level)
{
	crm_logger_t *ptr = crm_malloc(sizeof(crm_logger_t));
	ptr->level = level;
	ptr->mpsc = mpsc;
	ptr->tid = (crm_tid)pthread_self();
	return ptr;
}

void crm_logger_free(crm_logger_t *logger)
{
	crm_free(logger);
}

void crm_logger_log(LOG_LEVEL level, crm_logger_t *logger, const char *fmt, ...)
{
	va_list args;

	if (level < logger->level) {
		return;
	}

	// construct string, then send to mpsc
	// LEVEL date-time tid: MSG
	char msg[MAX_MSG_LEN - 64];
	char datetime[64];
	va_start(args, fmt);
	vsprintf(msg, fmt, args);
	va_end(args);

	time_t t;
	struct tm *now;
	time(&t);
	now = localtime(&t);
	strftime(datetime, sizeof(datetime), TIME_FORMAT, now);

	char *m = crm_malloc(sizeof(char) * MAX_MSG_LEN);
	sprintf(m, "[%s] %s %lu: %s", log_levels[logger->level], datetime,
		logger->tid, msg);
	crm_logger_msg_t *_msg = crm_logger_msg_new(m, logger->tid);

	crm_mpsc_send(logger->mpsc, _msg);
}

crm_logger_server_t *crm_logger_server_new(crm_logger_t *logger, FILE *output)
{
	crm_logger_server_t *ptr = crm_malloc(sizeof(crm_logger_server_t));
	ptr->logger = logger;
	ptr->output = output;
	return ptr;
}

void crm_logger_server_free(crm_logger_server_t *server)
{
	if (server->output != stderr && server->output != NULL) {
		fclose(server->output);
	}
	crm_logger_free(server->logger);
	crm_free(server);
}

// drain log and write to output
void crm_logger_server_serve(crm_logger_server_t *server)
{
	// FIXME: busy loop and sleep here
	// may use condvar and mutex
	while (1) {
		crm_logger_msg_t *msg = crm_mpsc_recv(server->logger->mpsc);
		if (msg != NULL) {
			fprintf(server->output, "%s\n", msg->msg);
		} else {
			sleep(1);
		}
	}
}

void *start_logger(void *logger)
{
	crm_logger_server_t *lserver =
		crm_logger_server_new((crm_logger_t *)logger, stderr);

	crm_logger_server_serve(lserver);

	return 0;
}
