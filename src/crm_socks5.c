#include "crm_socks5.h"

void crm_socks5_step(crm_socks5_t *s)
{
	unsigned char *rdata = s->rbuf;
	crm_size_t len = *s->read_bytes_ptr;

	switch (s->state) {
	case AUTH:
		if (len < 2 || rdata[0] != 0x5) {
			strcpy(s->err_msg, "invalid protocol");
			s->state = ERR;
		}
		strcpy((char *)s->wbuf, "\x05\x00");
		*s->write_bytes_ptr = 2;
		s->state = CMD;
		break;
	case CMD: {
		if (len < 7 || rdata[0] != 0x5 || rdata[2] != 0x0) {
			strcpy(s->err_msg, "invalid protocol");
			s->state = ERR;
		}
		switch (rdata[1]) {
		case 0x01: {
			// connect
			uint8_t atype = rdata[3];
			uint16_t port = rdata[len - 2] << 8 | rdata[len - 1];

			crm_memcpy((char *)s->wbuf, (const char *)s->rbuf, len);
			// write ack to local socket
			s->wbuf[1] = 0x00;

			s->state = PROXY;
			*s->write_bytes_ptr = len;
			// TODO: to the rest things

			break;
		}
		case 0x02: {
			// TODO: bind
		}
		case 0x03: {
			// TODO: udp associate
		}
		default:
			break;
		}
		break;
	}
	case PROXY:
		break;
	case ERR:
		break;
	default:
		break; // unreasonable
	}
}
