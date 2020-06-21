#include "crm_session.h"
#include "crm_log.h"
#include "unistd.h" // close
#include "crm_util.h"

/**
 * inbount event handler
 */
static void on_local_event(crm_bev_t *bev, short events, void *ctx)
{
	// free buffer event and related session
	crm_session_t *session = (crm_session_t *)ctx;
	if (events & BEV_EVENT_ERROR)
		crm_session_error(session, "Error from bufferevent");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		crm_bev_free(bev);
		crm_session_error(session, "EOF from local, free session");
		crm_session_free(session);
	}
}

/*
 * inbound on read handler
 * socks5 handshake -> proxy
 */
static void on_local_read(crm_bev_t *bev, void *ctx)
{
	crm_session_t *session = (crm_session_t *)ctx;
	crm_session_debug(session, "read triggered");
	// Socks5 local
	// Then choose server type
	struct evbuffer *output = crm_bev_get_output(bev);
	struct evbuffer *input = crm_bev_get_input(bev);

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
			on_local_event(bev, BEV_EVENT_ERROR, ctx);
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
			// create context, create session bound, do logic
			// TODO: server manager to pick a server config
			// server manager should take its own thread
			crm_server_config_t *config =
				&session->local_server->config->servers[0];
			session->outbound =
				crm_session_outbound_new(session, config);
		}
		return;
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
	ptr->inbound = crm_session_inbound_new(local_conn, bev);

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

	crm_bev_setcb(bev, on_local_read, NULL, on_local_event, session);
	crm_bev_enable(bev, EV_READ);
}

void crm_session_free(crm_session_t *session)
{
	if (session->inbound) {
		crm_session_inbound_free(session->inbound);
	}
	if (session->outbound) {
		crm_session_outbound_free(session->outbound);
	}
	crm_free(session);
}

crm_session_inbound_t *crm_session_inbound_new(crm_conn_t *conn, crm_bev_t *bev)
{
	crm_session_inbound_t *ptr = crm_malloc(sizeof(crm_session_inbound_t));
	ptr->conn = conn;
	ptr->bev = bev;
	return ptr;
}

void crm_session_inbound_free(crm_session_inbound_t *sb)
{
	if (sb->conn) {
		crm_conn_free(sb->conn);
	}
	if (sb->bev) {
		crm_bev_free(sb->bev);
	}
	crm_free(sb);
}

crm_trojansession_ctx_t *crm_trojansession_ctx_new(const char *encodepass,
						   crm_size_t passlen,
						   const char *cmd,
						   crm_size_t cmdlen)
{
	if (passlen != SHA224_LEN * 2 || cmdlen < 3)
		return NULL;
	crm_trojansession_ctx_t *ptr =
		crm_malloc(sizeof(crm_trojansession_ctx_t));
	// sha224(password) + "\r\n" + cmd[1] + cmd.substr(3) + "\r\n"
	ptr->head_len = passlen + 2 + 1 + cmdlen - 3 + 2;
	ptr->head = crm_malloc(sizeof(char) * ptr->head_len);
	char cmdslice[cmdlen - 3 + 1];
	crm_memcpy(cmdslice, cmd + 3, cmdlen - 3);
	cmdslice[cmdlen - 3 + 1 - 1] = '\0';
	sprintf(ptr->head, "%s\r\n%c%s\r\n", encodepass, cmd[1], cmdslice);
	return ptr;
}

void crm_trojansession_ctx_free(crm_trojansession_ctx_t *ctx)
{
	if (ctx->head)
		crm_free(ctx->head);
	ctx->head = NULL;
	crm_free(ctx);
	ctx = NULL;
}

crm_session_outbound_t *
crm_session_outbound_new(crm_session_t *session,
			 const crm_server_config_t *config)
{
	crm_session_outbound_t *ptr =
		crm_malloc(sizeof(crm_session_outbound_t));
	ptr->config = config;
	ptr->bev = crm_bev_socket_new(session->local_server->base, -1,
				      BEV_OPT_CLOSE_ON_FREE);
	ptr->ctx = NULL; // create ctx

	if (strcmp(config->server_type, "trojan") == 0) {
		ptr->ctx = crm_trojansession_ctx_new(
			config->password, 56,
			(const char *)session->inbound->conn->rbuf,
			session->inbound->conn->read_bytes);
		// set bev cb, and enable event
	}

	return ptr;
}

void crm_session_outbound_free(crm_session_outbound_t *ptr)
{
	if (ptr->bev)
		crm_bev_free(ptr->bev);
	if (ptr->ctx) {
		if (strcmp(ptr->config->server_type, "trojan") == 0) {
			crm_trojansession_ctx_free(ptr->ctx);
		}
	}
	ptr->bev = NULL;
	ptr->ctx = NULL;
	crm_free(ptr);
	ptr = NULL;
}
