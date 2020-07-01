#include "pgs_util.h"
#include "assert.h"

void test_sha224()
{
	// sha224("password") == "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
	char input[] = "password";
	char result[] =
		"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01";
	char buf[28];
	pgs_size_t res_len = 0;
	sha224((const pgs_buf_t *)input, 8, (pgs_buf_t *)buf, &res_len);
	pgs_buf_t *hexstring = to_hexstring((const pgs_buf_t *)buf, 28);
	assert(res_len == 28);
	assert(strcmp(result, (const char *)hexstring) == 0);
	pgs_free(hexstring);
}

void test_shake128()
{
	// shake128("", 256) == "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
	char input[] = "The quick brown fox jumps over the lazy dog";
	char result[] =
		"f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e";
	char buf[32];
	pgs_size_t res_len = 32;
	shake128((const pgs_buf_t *)input, strlen(input), (pgs_buf_t *)buf, res_len);
	pgs_buf_t *hexstring = to_hexstring((const pgs_buf_t *)buf, res_len);
	assert(strcmp(result, (const char *)hexstring) == 0);
	pgs_free(hexstring);
}

int main()
{
	test_sha224();
  test_shake128();
	return 0;
}
