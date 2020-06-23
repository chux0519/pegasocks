#ifndef _CRM_CORE
#define _CRM_CORE

#include <arpa/inet.h> // sockaddr type
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h> // memset
#include <stdlib.h> // malloc
#include <stdbool.h> // bool
#include <stdio.h> // FILE etc

#define _CRM_BUFSIZE 32 * 1024
#define _CRM_READ_BUFSZIE 32 * 1024
#define crm_memzero(buf, n) (void)memset(buf, 0, n)
#define crm_memcpy memcpy
#define crm_free free
#define crm_malloc malloc
#define crm_calloc calloc

typedef struct sockaddr crm_sockaddr_t;
typedef int crm_socket_t;
typedef pthread_t crm_thread_t;
typedef unsigned long crm_tid;
typedef unsigned char crm_buf_t;
typedef unsigned long long crm_size_t;
typedef SSL_CTX crm_ssl_ctx_t;
typedef SSL crm_ssl_t;

crm_ssl_ctx_t *crm_ssl_ctx_new();

crm_ssl_t *crm_ssl_new(crm_ssl_ctx_t *ctx, void *hostname);
void crm_ssl_close(crm_ssl_t *ssl);

#endif
