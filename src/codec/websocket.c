#include "codec/codec.h"
#include "crypto.h"

#include <assert.h>

#include <event2/buffer.h>

const char *ws_upgrade = "HTTP/1.1 101";
const char *ws_key = "dGhlIHNhbXBsZSBub25jZQ==";
const char *ws_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

void pgs_ws_req(struct evbuffer *out, const char *hostname,
		const char *server_address, int server_port, const char *path)
{
	// out, hostname, server_address, server_port, path
	evbuffer_add_printf(out, "GET %s HTTP/1.1\r\n", path);
	evbuffer_add_printf(out, "Host:%s:%d\r\n", hostname, server_port);
	evbuffer_add_printf(out, "Upgrade:websocket\r\n");
	evbuffer_add_printf(out, "Connection:upgrade\r\n");
	evbuffer_add_printf(out, "Sec-WebSocket-Key:%s\r\n", ws_key);
	evbuffer_add_printf(out, "Sec-WebSocket-Version:13\r\n");
	evbuffer_add_printf(
		out, "Origin:https://%s:%d\r\n", server_address,
		server_port); //missing this key will lead to 403 response.
	evbuffer_add_printf(out, "\r\n");
}

bool pgs_ws_upgrade_check(const char *data)
{
	return strncmp(data, ws_upgrade, strlen(ws_upgrade)) != 0 ||
	       !strstr(data, ws_accept);
}

void pgs_ws_write(struct evbuffer *buf, uint8_t *msg, uint64_t len, int opcode)
{
	pgs_ws_write_head(buf, len, opcode);
	// x ^ 0 = x
	evbuffer_add(buf, msg, len);
}

void pgs_ws_write_head(struct evbuffer *buf, uint64_t len, int opcode)
{
	uint8_t a = 0;
	a |= 1 << 7; //fin
	a |= opcode;

	uint8_t b = 0;
	b |= 1 << 7; //mask

	uint16_t c = 0;
	uint64_t d = 0;

	//payload len
	if (len < 126) {
		b |= len;
	} else if (len < (1 << 16)) {
		b |= 126;
		c = htons(len);
	} else {
		b |= 127;
		d = htonll(len);
	}

	evbuffer_add(buf, &a, 1);
	evbuffer_add(buf, &b, 1);

	if (c)
		evbuffer_add(buf, &c, sizeof(c));
	else if (d)
		evbuffer_add(buf, &d, sizeof(d));

	// tls will protect data
	// mask data makes nonsense
	uint8_t mask_key[4] = { 0, 0, 0, 0 };
	evbuffer_add(buf, &mask_key, 4);
}

bool pgs_ws_parse_head(uint8_t *data, uint64_t data_len, pgs_ws_resp_t *meta)
{
	meta->fin = !!(*data & 0x80);
	meta->opcode = *data & 0x0F;
	meta->mask = !!(*(data + 1) & 0x80);
	meta->payload_len = *(data + 1) & 0x7F;
	meta->header_len = 2 + (meta->mask ? 4 : 0);

	if (meta->payload_len < 126) {
		if (meta->header_len > data_len)
			return false;

	} else if (meta->payload_len == 126) {
		meta->header_len += 2;
		if (meta->header_len > data_len)
			return false;

		meta->payload_len = ntohs(*(uint16_t *)(data + 2));

	} else if (meta->payload_len == 127) {
		meta->header_len += 8;
		if (meta->header_len > data_len)
			return false;

		meta->payload_len = ntohll(*(uint64_t *)(data + 2));
	}

	if (meta->header_len + meta->payload_len > data_len)
		return false;

	const unsigned char *mask_key = data + meta->header_len - 4;

	for (int i = 0; meta->mask && i < meta->payload_len; i++)
		data[meta->header_len + i] ^= mask_key[i % 4];

	return true;
}
