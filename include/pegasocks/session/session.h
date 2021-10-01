#ifndef _PGS_SESSION_H
#define _PGS_SESSION_H

#include <netinet/in.h>
#include <event2/event.h>

#include "server/local.h"
#include "inbound.h"
#include "outbound.h"
#include "utils.h"

#define pgs_session_debug(session, ...)                                        \
	pgs_logger_debug(session->local_server->logger, __VA_ARGS__)
#define pgs_session_info(session, ...)                                         \
	pgs_logger_info(session->local_server->logger, __VA_ARGS__)
#define pgs_session_warn(session, ...)                                         \
	pgs_logger_warn(session->local_server->logger, __VA_ARGS__)
#define pgs_session_error(session, ...)                                        \
	pgs_logger_error(session->local_server->logger, __VA_ARGS__)
#define pgs_session_debug_buffer(session, buf, len)                            \
	pgs_logger_debug_buffer(session->local_server->logger, buf, len)

#define PGS_FREE_SESSION(session)                                              \
	pgs_list_del(session->local_server->sessions, session->node)

typedef struct pgs_server_session_stats_s {
	struct timeval start;
	struct timeval end;
	uint64_t send;
	uint64_t recv;
} pgs_session_stats_t;

typedef struct pgs_session_s {
	pgs_session_inbound_t *inbound;
	pgs_session_outbound_t *outbound;
	pgs_local_server_t *local_server;
	pgs_session_stats_t *metrics;

	pgs_list_node_t *node; /* store the value to sessions */
} pgs_session_t;

// session
pgs_session_t *pgs_session_new(int fd, pgs_local_server_t *local_server);
void pgs_session_start(pgs_session_t *session);
void pgs_session_free(pgs_session_t *session);

// metrics
void on_session_metrics_recv(pgs_session_t *session, uint64_t len);
void on_session_metrics_send(pgs_session_t *session, uint64_t len);

#endif
