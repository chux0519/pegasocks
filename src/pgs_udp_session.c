#include "pgs_udp_session.h"
#include "pgs_outbound.h"

pgs_udp_session_t *pgs_udp_session_new(int fd, pgs_local_server_t *local_server)
{
	// For each udp datagram we create a relative outbound tcp connection
	// So each udp datagram will wait the ws upgrade or stuff like that
	pgs_udp_session_t *ptr =
		(pgs_udp_session_t *)malloc(sizeof(pgs_udp_session_t));
	ptr->fd = fd;
	ptr->local_server = local_server;

	pgs_server_config_t *config =
		pgs_server_manager_get_config(local_server->sm);
	int config_idx = -1;
	for (int i = 0; i < local_server->config->servers_count; i++) {
		if (config == &local_server->config->servers[i]) {
			config_idx = i;
			break;
		}
	}
	// setup outbound
	//ptr->outbound = pgs_session_outbound_new(
	//	config, config_idx, cmd, cmd_len, local_server->logger,
	//	local_server->base, local_server->dns_base, outbound_cbs, ptr);
	// setup inbound

	return ptr;
}

void pgs_udp_session_free(pgs_udp_session_t *session)
{
	if (session->outbound != NULL) {
		pgs_session_outbound_free(session->outbound);
		session->outbound = NULL;
	}
	if (session != NULL) {
		free(session);
		session = NULL;
	}
}

void pgs_udp_session_start(pgs_udp_session_t *session)
{
}
