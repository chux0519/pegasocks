#ifndef _CRM_UTIL
#define _CRM_UTIL

#include "crm_core.h"

void sha224(const crm_buf_t *input, crm_size_t input_len, crm_buf_t *res,
	    crm_size_t *res_len);

crm_buf_t *to_hexstring(const crm_buf_t *buf, crm_size_t size);

#endif

