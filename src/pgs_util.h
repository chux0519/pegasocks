#ifndef _PGS_UTIL
#define _PGS_UTIL

#include "pgs_core.h"

#define SHA224_LEN 28

void sha224(const pgs_buf_t *input, pgs_size_t input_len, pgs_buf_t *res,
	    pgs_size_t *res_len);

pgs_buf_t *to_hexstring(const pgs_buf_t *buf, pgs_size_t size);

#endif

