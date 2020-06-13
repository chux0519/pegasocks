#include "crm_log.h"
#include "stdio.h"

void debug(unsigned char *buf, int size)
{
	for (int i = 0; i < size; i++) {
		printf("%02x ", (int)buf[i]);
	}
	printf("\n");
}
