#include "pgs_crypto.h"
#ifdef USE_MBEDTLS
#include <mbedtls/cipher.h>
#else
#include <openssl/evp.h>
#endif
#include "assert.h"

void test_sha224()
{
	// sha224("password") == "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
	char input[] = "password";
	char result[] =
		"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01";
	char buf[28];
	uint64_t res_len = 0;
	sha224((const uint8_t *)input, 8, (uint8_t *)buf, &res_len);
	uint8_t *hexstring = to_hexstring((const uint8_t *)buf, 28);
	assert(res_len == 28);
	assert(strcmp(result, (const char *)hexstring) == 0);
	free(hexstring);
}

void test_shake128()
{
	// shake128("", 256) == "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
	char input[] = "The quick brown fox jumps over the lazy dog";
	char result[] =
		"f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e";
	char buf[32];
	uint64_t res_len = 32;
	shake128((const uint8_t *)input, strlen(input), (uint8_t *)buf,
		 res_len);
	uint8_t *hexstring = to_hexstring((const uint8_t *)buf, res_len);
	assert(strcmp(result, (const char *)hexstring) == 0);
	free(hexstring);
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
	uint64_t res_len = 0;
	hmac_md5((const uint8_t *)key, 16, (const uint8_t *)data, 8,
		 (uint8_t *)buf, &res_len);
	uint8_t *hexstring = to_hexstring((const uint8_t *)buf, res_len);
	assert(res_len == 16);
	assert(strcmp(result, (const char *)hexstring) == 0);
	free(hexstring);
}

void test_md5()
{
	// md5("password") == "5f4dcc3b5aa765d61d8327deb882cf99"
	char input[] = "password";
	char result[] = "5f4dcc3b5aa765d61d8327deb882cf99";
	char buf[MD5_LEN];
	md5((const uint8_t *)input, 8, (uint8_t *)buf);
	uint8_t *hexstring = to_hexstring((const uint8_t *)buf, MD5_LEN);
	assert(strcmp(result, (const char *)hexstring) == 0);
	free(hexstring);
}

void test_fnv1a()
{
	// fnv1a32("password") = 0x364b5f18
	char input[] = "password";
	int res = fnv1a((void *)input, strlen(input));
	assert(res == 0x364b5f18);
}

void test_aes_128_cfb_encrypt()
{
	// key: key, iv: iviviviviviviviv
	// aes_128_cfb() == "960bb181638ddd77"
	char key[] = { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
	char iv[] = { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
	char plaintext[] = "password";
	char result[] = "960bb181638ddd77";
	unsigned char output[8];

	int output_len = aes_128_cfb_encrypt((const uint8_t *)plaintext, 8,
					     (const uint8_t *)key,
					     (const uint8_t *)iv, output);
	uint8_t *hexstring = to_hexstring((const uint8_t *)output, output_len);
	assert(strcmp(result, (const char *)hexstring) == 0);
	free(hexstring);
}

void test_aes_128_cfb_decrypt()
{
	// key: key, iv: iviviviviviviviv
	// aes_128_cfb() == "960bb181638ddd77"
	char key[] = { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
	char iv[] = { 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
	char ciphertext_hex[] = "960bb181638ddd77";
	char ciphertext[8];
	hextobin(ciphertext_hex, (uint8_t *)ciphertext, 8);
	char result[] = "password";
	unsigned char output[9];

	int output_len = aes_128_cfb_decrypt((const uint8_t *)ciphertext, 8,
					     (const uint8_t *)key,
					     (const uint8_t *)iv, output);
	assert(output_len == 8);
	output[8] = '\0';
	assert(strcmp(result, (const char *)output) == 0);
}

void test_crypto_aes()
{
}

void test_crypto_aead_encrypt()
{
	unsigned char key[16] = {
		1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8
	};
	unsigned char iv[12] = { 0, 0, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4 };
	unsigned char plaintext[8] = "password";
	unsigned char result1[8] = { 0x0b, 0x3b, 0x1e, 0x3b,
				     0x6f, 0x5e, 0xa3, 0x0c };
	unsigned char tag1[16] = { 0xa5, 0x33, 0x26, 0xb6, 0x34, 0xa1,
				   0x17, 0xf8, 0x78, 0xdc, 0x09, 0x0e,
				   0x76, 0x93, 0x47, 0x5e };
	pgs_aead_cryptor_t *encryptor;

#ifdef USE_MBEDTLS
	mbedtls_cipher_type_t cipher_gcm = MBEDTLS_CIPHER_AES_128_GCM;
	encryptor = pgs_aead_cryptor_new(&cipher_gcm, key, iv, PGS_ENCRYPT);
#else
	const EVP_CIPHER *cipher_gcm = EVP_aes_128_gcm();
	encryptor = pgs_aead_cryptor_new(cipher_gcm, key, iv, PGS_ENCRYPT);
#endif

	{
		// First round
		unsigned char en_tag[16] = { 0 };
		unsigned char out[8] = { 0 };
		int output_len;
		bool ret = pgs_aead_cryptor_encrypt(encryptor, plaintext, 8,
						    en_tag, out, &output_len);
		assert(ret == true);

		for (int i = 0; i < output_len; i++) {
			assert(out[i] == result1[i]);
		}

		for (int i = 0; i < 16; i++) {
			assert(en_tag[i] == tag1[i]);
		}
		assert(output_len == 8);
	}

	// Second round
	unsigned char iv2[12] = { 0, 1, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4 };
	unsigned char result2[8] = { 0x61, 0x16, 0xae, 0x97,
				     0x94, 0x0b, 0xdb, 0x65 };
	unsigned char tag2[16] = { 0x4a, 0xdd, 0x05, 0x86, 0xf8, 0x0d,
				   0x83, 0xb1, 0x1a, 0x3f, 0x25, 0xc4,
				   0x0f, 0xe2, 0xe7, 0x5a };
	{
		unsigned char en_tag[16] = { 0 };
		unsigned char out[8] = { 0 };
		int output_len;
		for (int i = 0; i < 12; i++) {
			assert(iv2[i] == encryptor->iv[i]);
		}

		assert(pgs_aead_cryptor_encrypt(encryptor, plaintext, 8, en_tag,
						out, &output_len) == true);

		for (int i = 0; i < 16; i++) {
			assert(en_tag[i] == tag2[i]);
		}

		assert(output_len == 8);
		for (int i = 0; i < output_len; i++) {
			assert(out[i] == result2[i]);
		}
	}

	pgs_aead_cryptor_free(encryptor);
}

void test_crypto_aead_decrypt()
{
	unsigned char key[16] = {
		1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8
	};
	unsigned char iv[12] = { 0, 0, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4 };
	unsigned char plaintext[8] = "password";
	unsigned char ciphertext[8] = { 0x0b, 0x3b, 0x1e, 0x3b,
					0x6f, 0x5e, 0xa3, 0x0c };
	unsigned char tag1[16] = { 0xa5, 0x33, 0x26, 0xb6, 0x34, 0xa1,
				   0x17, 0xf8, 0x78, 0xdc, 0x09, 0x0e,
				   0x76, 0x93, 0x47, 0x5e };

	pgs_aead_cryptor_t *decryptor;
#ifdef USE_MBEDTLS
	mbedtls_cipher_type_t cipher_gcm = MBEDTLS_CIPHER_AES_128_GCM;
	decryptor = pgs_aead_cryptor_new(&cipher_gcm, key, iv, PGS_DECRYPT);
#else
	const EVP_CIPHER *cipher_gcm = EVP_aes_128_gcm();
	decryptor = pgs_aead_cryptor_new(cipher_gcm, key, iv, PGS_DECRYPT);
#endif

	{
		// First round
		unsigned char out[8] = { 0 };
		int output_len;
		pgs_aead_cryptor_decrypt(decryptor, ciphertext, 8, tag1, out,
					 &output_len);

		assert(output_len == 8);
		for (int i = 0; i < output_len; i++) {
			assert(out[i] == plaintext[i]);
		}
	}

	// Second round
	unsigned char iv2[12] = { 0, 1, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4 };
	unsigned char ciphertext2[8] = { 0x61, 0x16, 0xae, 0x97,
					 0x94, 0x0b, 0xdb, 0x65 };
	unsigned char tag2[16] = { 0x4a, 0xdd, 0x05, 0x86, 0xf8, 0x0d,
				   0x83, 0xb1, 0x1a, 0x3f, 0x25, 0xc4,
				   0x0f, 0xe2, 0xe7, 0x5a };
	{
		unsigned char out[8] = { 0 };
		int output_len;
		for (int i = 0; i < 12; i++) {
			assert(iv2[i] == decryptor->iv[i]);
		}

		assert(pgs_aead_cryptor_decrypt(decryptor, ciphertext2, 8, tag2,
						out, &output_len) == true);

		for (int i = 0; i < output_len; i++) {
			assert(out[i] == plaintext[i]);
		}
		assert(output_len == 8);
	}

	pgs_aead_cryptor_free(decryptor);
}

void test_evp_bytes_to_key()
{
	const uint8_t input[] = "key";
	size_t input_len = 3;
	uint8_t output[32] = { 0 };
	size_t output_len = 32;
	const char *res =
		"3c6e0b8a9c15224a8228b9a98ca1531dd1e2a35fba509b6432edb96d850e119f";

	evp_bytes_to_key(input, input_len, output, output_len);
	uint8_t *hexstring = to_hexstring(output, output_len);
	assert(strcmp(res, (const char *)hexstring) == 0);
	free(hexstring);
}

int main()
{
	test_sha224();
	printf("test_sha224 passed\n");
	test_shake128();
	printf("test_shake128 passed\n");
	test_hmac_md5();
	printf("test_hmac_md5 passed\n");
	test_md5();
	printf("test_md5 passed\n");
	test_fnv1a();
	printf("test_fnv1a passed\n");
	test_aes_128_cfb_encrypt();
	printf("test_aes_128_cfb_encrypt passed\n");
	test_aes_128_cfb_decrypt();
	printf("test_aes_128_cfb_decrypt passed\n");
	test_crypto_aes();
	printf("test_crypto_aes passed\n");
	test_crypto_aead_encrypt();
	printf("test_crypto_aead_encrypt passed\n");
	test_crypto_aead_decrypt();
	printf("test_crypto_aead_decrypt passed\n");
	test_evp_bytes_to_key();
	printf("test_evp_bytes_to_key passed\n");
	return 0;
}
