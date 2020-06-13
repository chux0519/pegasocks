#include "crm_session.h"
#include "crm_log.h"

static void do_socks5_handshake(struct bufferevent *bev, void *ctx)
{
	printf("read triggered!\n");
	// Socks5 local
	// Then choose server type
	struct evbuffer *output = bufferevent_get_output(bev);
	struct evbuffer *input = bufferevent_get_input(bev);

	crm_session_t *session = (crm_session_t *)ctx;
	crm_conn_t *conn = session->conn;

	// read from local
	conn->read_bytes =
		evbuffer_remove(input, conn->rbuf, sizeof conn->rbuf);
	debug((unsigned char *)conn->rbuf, conn->read_bytes);

	// socks5 fsm
	// read write, set new bev callback
	crm_socks5_step(&session->fsm_socks5);
	if (session->fsm_socks5.state == PROXY) {
		// TODO: change cb, pass it to next handler
		printf("TODO: should tls handshake or ws\n");
	}
	if (session->fsm_socks5.state == ERR) {
		// TODO: error handling
		printf("TODO: ERR handling: %s\n", session->fsm_socks5.err_msg);
		// free buffer event
		// free session
		// close fd
	}
	// set write buffer
	evbuffer_add(output, conn->wbuf, conn->write_bytes);
}

static void other_session_event_cb(struct bufferevent *bev, short events,
				   void *ctx)
{
	if (events & BEV_EVENT_ERROR)
		perror("Error from bufferevent");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		bufferevent_free(bev);

		crm_session_t *session = (crm_session_t *)ctx;
		crm_session_free(session);
	}
}

crm_session_t *crm_session_new(crm_socket_t fd,
			       crm_local_server_t *local_server)
{
	crm_session_t *ptr = crm_malloc(sizeof(crm_session_t));
	ptr->conn = crm_conn_new(fd);
	ptr->local_server = local_server;

	// init socks5 structure
	ptr->fsm_socks5.rbuf = ptr->conn->rbuf;
	ptr->fsm_socks5.wbuf = ptr->conn->wbuf;
	ptr->fsm_socks5.read_bytes_ptr = &ptr->conn->read_bytes;
	ptr->fsm_socks5.write_bytes_ptr = &ptr->conn->write_bytes;

	return ptr;
}

void crm_session_start(crm_session_t *session)
{
	// using ev related things
	// socks5 setup, then do proxy

	// new connection, setup a bufferevent for it
	crm_bev_t *bev = crm_bev_socket_new(session, 0);

	// TODO: create task
	// add callbacks: socks5, tls things, wss

	// after socks5 end, pass fd to remains
	// TODO: how to do composed operations
	// using a state machine ?
	// dynamicly setcb, state: stage_1, then do stage_1_cb
	// state: stage_2, then do statge_2_cb
	// like: crm_bev_set_cbs(bev, {stage_1: handler_1, stage_2: handler})
	// task {next, handler, ctx}
	bufferevent_setcb(bev, do_socks5_handshake, NULL,
			  other_session_event_cb, session);
	bufferevent_enable(bev, EV_READ);
}

void crm_session_free(crm_session_t *session)
{
	if (session->conn) {
		crm_conn_free(session->conn);
	}
	crm_free(session);
}

