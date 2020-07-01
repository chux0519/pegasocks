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
	shake128((const pgs_buf_t *)input, strlen(input), (pgs_buf_t *)buf,
		 res_len);
	pgs_buf_t *hexstring = to_hexstring((const pgs_buf_t *)buf, res_len);
	assert(strcmp(result, (const char *)hexstring) == 0);
	pgs_free(hexstring);
}

void test_hmac_md5()
{
	// test_case =     1
	// key =           0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
	// key_len =       16
	// data =          "Hi There"
	// data_len =      8
	// digest =        0x9294727a3638bb1c13f48ef8158bfc9d
	char key[16];
	for (int i = 0; i < 16; i++) {
		key[i] = 0x0b;
	}
	char data[] = "Hi There";
	char result[] = "9294727a3638bb1c13f48ef8158bfc9d";
	char buf[16];
	pgs_size_t res_len = 0;
	hmac_md5((const pgs_buf_t *)key, 16, (const pgs_buf_t *)data, 8,
		 (pgs_buf_t *)buf, &res_len);
	pgs_buf_t *hexstring = to_hexstring((const pgs_buf_t *)buf, res_len);
	assert(res_len == 16);
	assert(strcmp(result, (const char *)hexstring) == 0);
	pgs_free(hexstring);
}

void test_md5()
{
	// md5("password") == "5f4dcc3b5aa765d61d8327deb882cf99"
	char input[] = "password";
	char result[] = "5f4dcc3b5aa765d61d8327deb882cf99";
	char buf[MD5_LEN];
	md5((const pgs_buf_t *)input, 8, (pgs_buf_t *)buf);
	pgs_buf_t *hexstring = to_hexstring((const pgs_buf_t *)buf, MD5_LEN);
	assert(strcmp(result, (const char *)hexstring) == 0);
	pgs_free(hexstring);
}

void test_fnv1a()
{
	// fnv1a("password") == "5f4dcc3b5aa765d61d8327deb882cf99"
	char input[] = "password";
	char result[] = "364b5f18";
	int res = fnv1a((void *)input, strlen(input));
	char hexstring[4];
	sprintf(hexstring, "%08x", res);
	assert(strcmp(result, (const char *)hexstring) == 0);
}

int main()
{
	test_sha224();
	test_shake128();
	test_hmac_md5();
	test_md5();
	test_fnv1a();
	return 0;
}
