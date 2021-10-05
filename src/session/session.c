#include "codec/codec.h"
#include "crypto.h"
#include "defs.h"
#include "session/session.h"
#include "server/manager.h"
#include "log.h"
#include "session/udp.h"
#include "session/session.h"

#include <unistd.h>
#include <assert.h>
#include <ctype.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/**
 * Create New Sesson
 *
 * @param fd the local socket fd
 * @param local_address the local_server object
 *  which contains logger, base, etc..
 * @return a pointer of new session
 */
pgs_session_t *pgs_session_new(int fd, pgs_local_server_t *local_server)
{
	pgs_session_t *ptr = malloc(sizeof(pgs_session_t));

	struct bufferevent *bev = bufferevent_socket_new(local_server->base, fd,
							 BEV_OPT_CLOSE_ON_FREE);
	ptr->inbound = pgs_session_inbound_new(bev);
	ptr->outbound = NULL;

	// init metrics
	ptr->metrics = malloc(sizeof(pgs_session_stats_t));
	gettimeofday(&ptr->metrics->start, NULL);
	gettimeofday(&ptr->metrics->end, NULL);
	ptr->metrics->recv = 0;
	ptr->metrics->send = 0;
	ptr->local_server = local_server;

	ptr->node = pgs_list_node_new(ptr);

	return ptr;
}

/**
 * Start session
 *
 * it will set event callbacks for local socket fd
 * then enable READ event
 */
void pgs_session_start(pgs_session_t *session)
{
	pgs_session_inbound_start(session->inbound, session);
}

void pgs_session_free(pgs_session_t *session)
{
	if (session->outbound) {
		gettimeofday(&session->metrics->end, NULL);
		char tm_start_str[20], tm_end_str[20];
		PARSE_SESSION_TIMEVAL(tm_start_str, session->metrics->start);
		PARSE_SESSION_TIMEVAL(tm_end_str, session->metrics->end);
		if (session->inbound &&
		    session->inbound->state != INBOUND_UDP_RELAY) {
			pgs_session_info(
				session,
				"connection to %s:%d closed, start: %s, end: %s, send: %d, recv: %d",
				session->outbound->dest,
				session->outbound->port, tm_start_str,
				tm_end_str, session->metrics->send,
				session->metrics->recv);
		}
		if (session->inbound)
			pgs_session_inbound_free(session->inbound);

		session->inbound = NULL;
		pgs_session_outbound_free(session->outbound);
	}
	if (session->inbound)
		pgs_session_inbound_free(session->inbound);

	if (session->metrics)
		free(session->metrics);

	free(session);
}

void on_session_metrics_recv(pgs_session_t *session, uint64_t len)
{
	if (!session->metrics)
		return;
	session->metrics->recv += len;
}

void on_session_metrics_send(pgs_session_t *session, uint64_t len)
{
	if (!session->metrics)
		return;
	session->metrics->send += len;
}
