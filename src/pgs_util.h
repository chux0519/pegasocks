#ifndef _PGS_UTIL
#define _PGS_UTIL

#include "pgs_core.h"

#define SHA224_LEN 28
#define MD5_LEN 16
#define LTRIM(addr)                                                            \
	while (isspace(*addr))                                                 \
		addr++;

void sha224(const pgs_buf_t *input, pgs_size_t input_len, pgs_buf_t *res,
	    pgs_size_t *res_len);

void shake128(const pgs_buf_t *input, pgs_size_t input_len, pgs_buf_t *out,
	      pgs_size_t out_len);

void md5(const pgs_buf_t *input, pgs_size_t input_len, pgs_buf_t *res);

void hmac_md5(const pgs_buf_t *key, pgs_size_t key_len, const pgs_buf_t *data,
	      pgs_size_t data_len, pgs_buf_t *out, pgs_size_t *out_len);

pgs_buf_t *to_hexstring(const pgs_buf_t *buf, pgs_size_t size);

#endif
