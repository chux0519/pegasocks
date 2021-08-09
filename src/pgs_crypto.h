#ifndef _PGS_CRYPTO
#define _PGS_CRYPTO

#include "pgs_defs.h"
#include "../3rd-party/sha3.h"
#include "../3rd-party/fnv.h"

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/ssl.h>

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#define SHA224_LEN 28
#define MD5_LEN 16
#define AES_128_CFB_KEY_LEN 16
#define AES_128_CFB_IV_LEN 16

typedef struct pgs_base_cryptor_s pgs_base_cryptor_t;
typedef struct pgs_base_cryptor_s pgs_aes_cryptor_t;
typedef struct pgs_aead_cryptor_s pgs_aead_cryptor_t;
typedef enum { PGS_ENCRYPT, PGS_DECRYPT } pgs_cryptor_direction_t;

struct pgs_base_cryptor_s {
	EVP_CIPHER_CTX *ctx;
	const uint8_t *key;
	const uint8_t *iv;
};

struct pgs_aead_cryptor_s {
	EVP_CIPHER_CTX *ctx;
	const uint8_t *key;
	uint8_t *iv;
	pgs_cryptor_direction_t dir;
	uint16_t counter;
};

/* AES cipher */
pgs_aes_cryptor_t *pgs_aes_cryptor_new(const EVP_CIPHER *cipher,
				       const uint8_t *key, const uint8_t *iv,
				       pgs_cryptor_direction_t dir);
void pgs_aes_cryptor_free(pgs_aes_cryptor_t *ptr);
bool pgs_aes_cryptor_encrypt(pgs_aes_cryptor_t *ptr, const uint8_t *plaintext,
			     int plaintext_len, uint8_t *ciphertext);
bool pgs_aes_cryptor_encrypt_final(pgs_aes_cryptor_t *ptr,
				   const uint8_t *plaintext, int plaintext_len,
				   uint8_t *ciphertext);
bool pgs_aes_cryptor_decrypt(pgs_aes_cryptor_t *ptr, const uint8_t *ciphertext,
			     int ciphertext_len, uint8_t *plaintext);
bool pgs_aes_cryptor_decrypt_final(pgs_aes_cryptor_t *ptr,
				   const uint8_t *ciphertext,
				   int ciphertext_len, uint8_t *plaintext);

/* AEAD cipher */
pgs_aead_cryptor_t *pgs_aead_cryptor_new(const EVP_CIPHER *cipher,
					 const uint8_t *key, const uint8_t *iv,
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

static void sha224(const uint8_t *input, uint64_t input_len, uint8_t *res,
	    uint64_t *res_len);


		void sha224(const uint8_t *input, uint64_t input_len, uint8_t *res,
	    uint64_t *res_len)
{
	EVP_MD_CTX *ctx;
	if ((ctx = EVP_MD_CTX_new()) == NULL)
		goto error;
	if (!EVP_DigestInit_ex(ctx, EVP_sha224(), NULL))
		goto error;
	if (!EVP_DigestUpdate(ctx, input, input_len))
		goto error;
	if (!EVP_DigestFinal_ex(ctx, res, (unsigned int *)res_len))
		goto error;

	EVP_MD_CTX_free(ctx);
	return;

error:
	perror("error sha224");
	if (ctx != NULL)
		EVP_MD_CTX_free(ctx);
	*res_len = 0;
}

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

static void md5(const uint8_t *input, uint64_t input_len, uint8_t *res)
{
	MD5(input, input_len, res);
}

static void hmac_md5(const uint8_t *key, uint64_t key_len, const uint8_t *data,
	      uint64_t data_len, uint8_t *out, uint64_t *out_len)
{
	HMAC(EVP_md5(), key, key_len, data, data_len, out,
	     (unsigned int *)out_len);
	assert(*out_len == 16);
}

static int fnv1a(void *input, uint64_t input_len)
{
	return fnv_32a_buf(input, input_len, FNV1_32A_INIT);
}

static int aes_128_cfb_encrypt(const uint8_t *plaintext, int plaintext_len,
			const uint8_t *key, const uint8_t *iv,
			uint8_t *ciphertext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new()))
		goto error;

	/*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits 16bytes
     */
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, key, iv))
		goto error;

	/*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
	if (1 !=
	    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		goto error;
	ciphertext_len = len;

	/*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		goto error;
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;

error:
	perror("aes_128_cfb_encrypt");
	return -1;
}

static int aes_128_cfb_decrypt(const uint8_t *ciphertext, int ciphertext_len,
			const uint8_t *key, const uint8_t *iv,
			uint8_t *plaintext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int plaintext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new()))
		goto error;

	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, key, iv))
		goto error;

	if (1 !=
	    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		goto error;
	plaintext_len = len;

	if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
		goto error;
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;

error:
	perror("aes_128_cfb_decrypt");
	return -1;
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
