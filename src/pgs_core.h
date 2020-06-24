#ifndef _PGS_CORE
#define _PGS_CORE

#include <arpa/inet.h> // sockaddr type
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h> // memset
#include <stdlib.h> // malloc
#include <stdbool.h> // bool
#include <stdio.h> // FILE etc

#define _PGS_BUFSIZE 32 * 1024
#define _PGS_READ_BUFSZIE 32 * 1024
#define pgs_memzero(buf, n) (void)memset(buf, 0, n)
#define pgs_memcpy memcpy
#define pgs_free free
#define pgs_malloc malloc
#define pgs_calloc calloc

typedef struct sockaddr pgs_sockaddr_t;
typedef int pgs_socket_t;
typedef pthread_t pgs_thread_t;
typedef unsigned long pgs_tid;
typedef unsigned char pgs_buf_t;
typedef unsigned long long pgs_size_t;
typedef SSL_CTX pgs_ssl_ctx_t;
typedef SSL pgs_ssl_t;

pgs_ssl_ctx_t *pgs_ssl_ctx_new();

pgs_ssl_t *pgs_ssl_new(pgs_ssl_ctx_t *ctx, void *hostname);
void pgs_ssl_close(pgs_ssl_t *ssl);

#endif
