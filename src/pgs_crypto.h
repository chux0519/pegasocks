#ifndef _PGS_CRYPTO
#define _PGS_CRYPTO

#include "pgs_defs.h"
#include "pgs_config.h"
#include "sha3.h"
#include "fnv.h"

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#define SHA224_LEN 28
#define MD5_LEN 16
#define AES_128_CFB_KEY_LEN 16
#define AES_128_CFB_IV_LEN 16

typedef struct pgs_base_cryptor_s pgs_aes_cryptor_t;
typedef enum { PGS_ENCRYPT, PGS_DECRYPT } pgs_cryptor_direction_t;

typedef struct pgs_base_cryptor_s {
	// EVP_CIPHER_CTX for openssl
	void *ctx;
	const uint8_t *key;
	const uint8_t *iv;
} pgs_base_cryptor_t;

typedef struct pgs_aead_cryptor_s {
	void *ctx;
	const uint8_t *key;
	uint8_t *iv;
	pgs_cryptor_direction_t dir;
	uint16_t counter;
} pgs_aead_cryptor_t;

pgs_base_cryptor_t *pgs_cryptor_new(pgs_v2ray_secure_t secure,
				    const uint8_t *key, const uint8_t *iv,
				    pgs_cryptor_direction_t dir);
void pgs_cryptor_free(pgs_v2ray_secure_t secure, pgs_base_cryptor_t *cryptor);

/* AES cipher */
pgs_aes_cryptor_t *pgs_aes_cryptor_new(const void *cipher, const uint8_t *key,
				       const uint8_t *iv,
				       pgs_cryptor_direction_t dir);
void pgs_aes_cryptor_free(pgs_aes_cryptor_t *ptr);
bool pgs_aes_cryptor_encrypt(pgs_aes_cryptor_t *ptr, const uint8_t *plaintext,
			     int plaintext_len, uint8_t *ciphertext);
bool pgs_aes_cryptor_encrypt_final(pgs_aes_cryptor_t *ptr, uint8_t *ciphertext);
bool pgs_aes_cryptor_decrypt(pgs_aes_cryptor_t *ptr, const uint8_t *ciphertext,
			     int ciphertext_len, uint8_t *plaintext);
bool pgs_aes_cryptor_decrypt_final(pgs_aes_cryptor_t *ptr, uint8_t *plaintext);

/* AEAD cipher */
pgs_aead_cryptor_t *pgs_aead_cryptor_new(const void *cipher, const uint8_t *key,
					 const uint8_t *iv,
					 pgs_cryptor_direction_t dir);
void pgs_aead_cryptor_free(pgs_aead_cryptor_t *ptr);
bool pgs_aead_cryptor_encrypt(pgs_aead_cryptor_t *ptr, const uint8_t *plaintext,
			      int plaintext_len, uint8_t *tag,
			      uint8_t *ciphertext, int *ciphertext_len);
bool pgs_aead_cryptor_decrypt(pgs_aead_cryptor_t *ptr,
			      const uint8_t *ciphertext, int ciphertext_len,
			      const uint8_t *tag, uint8_t *plaintext,
			      int *plaintext_len);
void pgs_aead_cryptor_increase_iv(pgs_aead_cryptor_t *ptr);

/* helpers */

int rand_bytes(unsigned char *buf, int num);
void sha224(const uint8_t *input, uint64_t input_len, uint8_t *res,
	    uint64_t *res_len);
void md5(const uint8_t *input, uint64_t input_len, uint8_t *res);
void hmac_md5(const uint8_t *key, uint64_t key_len, const uint8_t *data,
	      uint64_t data_len, uint8_t *out, uint64_t *out_len);
int aes_128_cfb_encrypt(const uint8_t *plaintext, int plaintext_len,
			const uint8_t *key, const uint8_t *iv,
			uint8_t *ciphertext);
int aes_128_cfb_decrypt(const uint8_t *ciphertext, int ciphertext_len,
			const uint8_t *key, const uint8_t *iv,
			uint8_t *plaintext);

/* shadowsocks password to subpass transform */
static void evp_bytes_to_key(const uint8_t *input, size_t input_len,
			     uint8_t *key, size_t key_len)
{
	uint8_t round_res[16] = { 0 };
	size_t cur_pos = 0;

	uint8_t *buf = (uint8_t *)malloc(input_len + 16);
	memcpy(buf, input, input_len);

	while (cur_pos < key_len) {
		if (cur_pos == 0) {
			md5(buf, input_len, round_res);
		} else {
			memcpy(buf, round_res, 16);
			memcpy(buf + 16, input, input_len);
			md5(buf, input_len + 16, round_res);
		}
		for (int p = cur_pos; p < key_len && p < cur_pos + 16; p++) {
			key[p] = round_res[p - cur_pos];
		}
		cur_pos += 16;
	}
	free(buf);
}

// =========================== static helpers

static void shake128(const uint8_t *input, uint64_t input_len, uint8_t *out,
		     uint64_t out_len)
{
	sha3_ctx_t sha3;
	shake128_init(&sha3);
	shake_update(&sha3, input, input_len);
	shake_xof(&sha3);
	shake_out(&sha3, out, out_len);
	return;
}

static int fnv1a(void *input, uint64_t input_len)
{
	return fnv_32a_buf(input, input_len, FNV1_32A_INIT);
}

static uint8_t *to_hexstring(const uint8_t *buf, uint64_t size)
{
	uint8_t *hexbuf = (uint8_t *)malloc(sizeof(uint8_t) * (2 * size + 1));
	for (int i = 0; i < size; i++) {
		sprintf((char *)hexbuf + i * 2, "%02x", (int)buf[i]);
	}
	hexbuf[2 * size] = '\0';
	return hexbuf;
}

static void hextobin(const char *str, uint8_t *bytes, size_t blen)
{
	uint8_t pos;
	uint8_t idx0;
	uint8_t idx1;

	// mapping of ASCII characters to hex values
	const uint8_t hashmap[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  !"#$%&'
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ()*+,-./
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567
		0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?
		0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // @ABCDEFG
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // HIJKLMNO
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PQRSTUVW
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // XYZ[\]^_
		0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // `abcdefg
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hijklmno
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // pqrstuvw
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // xyz{|}~.
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // ........
	};

	memzero(bytes, blen);
	for (pos = 0; (pos < (blen * 2)); pos += 2) {
		idx0 = (uint8_t)str[pos + 0];
		idx1 = (uint8_t)str[pos + 1];
		bytes[pos / 2] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
	};
}
#endif
