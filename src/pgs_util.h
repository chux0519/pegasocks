#ifndef _PGS_UTIL
#define _PGS_UTIL

#include "pgs_core.h"

#define SHA224_LEN 28
#define MD5_LEN 16
#define AES_128_CFB_KEY_LEN 16
#define AES_128_CFB_IV_LEN 16
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

int fnv1a(void *input, pgs_size_t input_len);

int aes_128_cfb_encrypt(const pgs_buf_t *plaintext, int plaintext_len,
			const pgs_buf_t *key, const pgs_buf_t *iv,
			pgs_buf_t *ciphertext);

int aes_128_cfb_decrypt(const pgs_buf_t *ciphertext, int ciphertext_len,
			const pgs_buf_t *key, const pgs_buf_t *iv,
			pgs_buf_t *plaintext);

pgs_buf_t *to_hexstring(const pgs_buf_t *buf, pgs_size_t size);

void hextobin(const char *str, uint8_t *bytes, size_t blen);

char *socks5_dest_addr_parse(const pgs_buf_t *cmd, pgs_size_t cmd_len);

#endif
