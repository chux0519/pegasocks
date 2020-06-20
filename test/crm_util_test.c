#include "crm_util.h"
#include "assert.h"

void test_sha224()
{
	// sha224("password") == "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
	char input[] = "password";
	char result[] =
		"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01";
	char buf[28];
	crm_size_t res_len = 0;
	sha224((const crm_buf_t *)input, 8, (crm_buf_t *)buf, &res_len);
	crm_buf_t *hexstring = to_hexstring((const crm_buf_t *)buf, 28);
	assert(res_len == 28);
	assert(strcmp(result, (const char *)hexstring) == 0);
	crm_free(hexstring);
}

int main()
{
	test_sha224();
	return 0;
}
