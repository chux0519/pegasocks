#include "crm_session.h"
#include "crm_log.h"
#include "unistd.h" // close

/*
 * inbound on read handler
 * socks5 handshake -> proxy
 */
static void on_local_read(struct bufferevent *bev, void *ctx)
{
	crm_session_t *session = (crm_session_t *)ctx;
	crm_session_debug(session, "read triggered");
	// Socks5 local
	// Then choose server type
	struct evbuffer *output = bufferevent_get_output(bev);
	struct evbuffer *input = bufferevent_get_input(bev);

	crm_conn_t *conn = session->inbound->conn;

	// read from local
	conn->read_bytes =
		evbuffer_remove(input, conn->rbuf, sizeof conn->rbuf);
	crm_session_debug_buffer(session, (unsigned char *)conn->rbuf,
				 conn->read_bytes);

	if (session->fsm_socks5.state != PROXY) {
		// socks5 fsm
		crm_socks5_step(&session->fsm_socks5);
		if (session->fsm_socks5.state == ERR) {
			crm_session_error(session, "%s",
					  session->fsm_socks5.err_msg);
			other_session_event_cb(bev, BEV_EVENT_ERROR, ctx);
		}
		// repsond to local socket
		evbuffer_add(output, conn->wbuf, conn->write_bytes);
		if (session->fsm_socks5.state == PROXY) {
			crm_session_debug(session,
					  "TODO: should tls handshake or ws");
			// outbound comes in at this point
			// add header to trojan write buffer
			// using local read buffer(CMD) construct outbound session context
			// create new session then start
			// change local bev read callback to relative callback
		}
		return;
	}
}

/**
 * EOF and ERROR handler
 */
static void other_session_event_cb(struct bufferevent *bev, short events,
				   void *ctx)
{
	// free buffer event and related session
	crm_session_t *session = (crm_session_t *)ctx;
	if (events & BEV_EVENT_ERROR)
		crm_session_error(session, "Error from bufferevent");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		bufferevent_free(bev);

		crm_session_free(session);
	}
}

/**
 * Create New Sesson
 *
 * @param fd the local socket fd
 * @param local_address the local_server object
 *  which contains logger, base, etc..
 * @return a pointer of new session
 */
crm_session_t *crm_session_new(crm_socket_t fd,
			       crm_local_server_t *local_server)
{
	crm_session_t *ptr = crm_malloc(sizeof(crm_session_t));

	crm_conn_t *local_conn = crm_conn_new(fd);
	crm_bev_t *bev = crm_bev_socket_new(local_server->base, fd,
					    BEV_OPT_CLOSE_ON_FREE);
	ptr->inbound = crm_session_bound_new(local_conn, bev);

	ptr->outbound = NULL;

	ptr->local_server = local_server;

	// init socks5 structure
	ptr->fsm_socks5.rbuf = ptr->inbound->conn->rbuf;
	ptr->fsm_socks5.wbuf = ptr->inbound->conn->wbuf;
	ptr->fsm_socks5.read_bytes_ptr = &ptr->inbound->conn->read_bytes;
	ptr->fsm_socks5.write_bytes_ptr = &ptr->inbound->conn->write_bytes;

	return ptr;
}

/**
 * Start session
 *
 * it will set event callbacks for local socket fd
 * then enable READ event
 */
void crm_session_start(crm_session_t *session)
{
	// new connection, setup a bufferevent for it
	crm_bev_t *bev = session->inbound->bev;

	// socks5 handshake
	bufferevent_setcb(bev, on_local_read, NULL, other_session_event_cb,
			  session);
	bufferevent_enable(bev, EV_READ);
}

void crm_session_free(crm_session_t *session)
{
	if (session->inbound) {
		crm_session_bound_free(session->inbound);
	}
	if (session->outbound) {
		crm_session_bound_free(session->outbound);
	}
	crm_free(session);
}

crm_session_bound_t *crm_session_bound_new(crm_conn_t *conn, crm_bev_t *bev)
{
	crm_session_bound_t *ptr = crm_malloc(sizeof(crm_session_bound_t));
	ptr->conn = conn;
	ptr->bev = bev;
	ptr->ctx = NULL;
	return ptr;
}

void crm_session_bound_free(crm_session_bound_t *sb)
{
	if (sb->conn) {
		crm_conn_free(sb->conn);
	}
	if (sb->bev) {
		crm_bev_free(sb->bev);
	}
	if (sb->ctx) {
		crm_free(sb->ctx);
	}
	crm_free(sb);
}
