#ifndef _PGS_UTIL
#define _PGS_UTIL

#include "pgs_defs.h"

#include <stdint.h>

#define SHA224_LEN 28
#define MD5_LEN 16
#define AES_128_CFB_KEY_LEN 16
#define AES_128_CFB_IV_LEN 16
#define LTRIM(addr)                                                            \
	while (isspace(*addr))                                                 \
		addr++;

void sha224(const uint8_t *input, uint64_t input_len, uint8_t *res,
	    uint64_t *res_len);

void shake128(const uint8_t *input, uint64_t input_len, uint8_t *out,
	      uint64_t out_len);

void md5(const uint8_t *input, uint64_t input_len, uint8_t *res);

void hmac_md5(const uint8_t *key, uint64_t key_len, const uint8_t *data,
	      uint64_t data_len, uint8_t *out, uint64_t *out_len);

int fnv1a(void *input, uint64_t input_len);

int aes_128_cfb_encrypt(const uint8_t *plaintext, int plaintext_len,
			const uint8_t *key, const uint8_t *iv,
			uint8_t *ciphertext);

int aes_128_cfb_decrypt(const uint8_t *ciphertext, int ciphertext_len,
			const uint8_t *key, const uint8_t *iv,
			uint8_t *plaintext);

uint8_t *to_hexstring(const uint8_t *buf, uint64_t size);

void hextobin(const char *str, uint8_t *bytes, size_t blen);

char *socks5_dest_addr_parse(const uint8_t *cmd, uint64_t cmd_len);

#endif
