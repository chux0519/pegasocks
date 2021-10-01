#include "codec/codec.h"
#include "crypto.h"

#include <event2/buffer.h>

bool trojan_write_remote(pgs_session_t *session, const uint8_t *msg, size_t len,
			 size_t *olen)
{
	struct bufferevent *outbev = session->outbound->bev;
	struct evbuffer *outboundw = bufferevent_get_output(outbev);
	pgs_outbound_ctx_trojan_t *trojan_s_ctx = session->outbound->ctx;
	size_t head_len = trojan_s_ctx->head_len;
	if (head_len > 0) {
		evbuffer_add(outboundw, trojan_s_ctx->head, head_len);
		trojan_s_ctx->head_len = 0;
	}
	evbuffer_add(outboundw, msg, len);

	pgs_session_debug(session, "local -> remote: %d", len + head_len);

	*olen = len + head_len;
	return true;
}

bool trojan_write_local(pgs_session_t *session, const uint8_t *msg, size_t len,
			size_t *olen)
{
	uint8_t *udp_packet = NULL;
	if (session->inbound->state == INBOUND_PROXY) {
		struct bufferevent *inbev = session->inbound->bev;
		struct evbuffer *inboundw = bufferevent_get_output(inbev);
		evbuffer_add(inboundw, msg, len);
		pgs_session_debug(session, "remote -> local: %d", len);
		*olen = len;
	} else if (session->inbound->state == INBOUND_UDP_RELAY &&
		   session->inbound->udp_fd != -1) {
		// decode trojan udp packet
		uint8_t atype = msg[0];
		uint16_t addr_len = 1 + 2; // atype + port
		addr_len += pgs_get_addr_len(msg);
		uint16_t payload_len = msg[addr_len] << 8 | msg[addr_len + 1];
		if (len < (addr_len + 2 + 2 + payload_len) ||
		    msg[addr_len + 2] != '\r' || msg[addr_len + 3] != '\n') {
			pgs_session_error(
				session,
				"payload too large or invalid response");
			goto error;
		}
		// pack socks5 udp reply
		uint16_t udp_packet_len = 2 + 1 + addr_len + payload_len;
		udp_packet = malloc(udp_packet_len);
		if (udp_packet == NULL) {
			pgs_session_error(session, "out of memory");
			goto error;
		}
		udp_packet[0] = 0x00;
		udp_packet[1] = 0x00;
		udp_packet[2] = 0x00;
		memcpy(udp_packet + 3, msg, addr_len);
		memcpy(udp_packet + 3 + addr_len, msg + addr_len + 4,
		       payload_len);
		int n = sendto(
			session->inbound->udp_fd, udp_packet, udp_packet_len, 0,
			(struct sockaddr *)&session->inbound->udp_client_addr,
			session->inbound->udp_client_addr_size);
		pgs_session_debug(session, "write %d bytes to local udp sock",
				  n);
		*olen = n;
		free(udp_packet);
	}
	return true;

error:
	if (udp_packet != NULL) {
		free(udp_packet);
		udp_packet = NULL;
	}
	return false;
}
