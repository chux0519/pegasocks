#ifndef _PGS_CORE
#define _PGS_CORE

#include <arpa/inet.h> // sockaddr type
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h> // memset
#include <stdlib.h> // malloc
#include <stdbool.h> // bool
#include <stdio.h> // FILE etc
#include <pthread.h>

#define BUFSIZE_16K 16 * 1024
#define memzero(buf, n) (void)memset(buf, 0, n)

typedef unsigned long pgs_tid;
typedef unsigned char pgs_buf_t;
typedef unsigned long long pgs_size_t;

SSL_CTX *pgs_ssl_ctx_new();
SSL *pgs_ssl_new(SSL_CTX *ctx, void *hostname);
void pgs_ssl_close(SSL *ssl);

#endif
