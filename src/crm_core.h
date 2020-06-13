#ifndef _CRM_CORE
#define _CRM_CORE

#include <arpa/inet.h> // sockaddr type
#include <string.h> // memset

#define _CRM_BUFSIZE 32 * 1024
#define _CRM_READ_BUFSZIE 16 * 1024
#define crm_memzero(buf, n) (void)memset(buf, 0, n)

typedef struct sockaddr crm_sockaddr_t;
typedef int crm_socket_t;

typedef unsigned char *crm_buf_t;

#endif
