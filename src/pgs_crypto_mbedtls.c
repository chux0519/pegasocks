#include "pgs_crypto.h"

#include <stdlib.h>
#include <time.h>
#include <mbedtls/cipher.h>
#include <mbedtls/gcm.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md5.h>
#include <mbedtls/sha1.h>
#include <mbedtls/md.h>
#include <mbedtls/hkdf.h>

pgs_base_cryptor_t *pgs_cryptor_new(pgs_v2ray_secure_t secure,
				    const uint8_t *key, const uint8_t *iv,
				    pgs_cryptor_direction_t dir)
{
	switch (secure) {
	case V2RAY_SECURE_CFB: {
		mbedtls_cipher_type_t cipher_cfb =
			MBEDTLS_CIPHER_AES_128_CFB128;
		return pgs_aes_cryptor_new(&cipher_cfb, key, iv, dir);
	}
	case V2RAY_SECURE_GCM: {
		mbedtls_cipher_type_t cipher_gcm = MBEDTLS_CIPHER_AES_128_GCM;
		return (pgs_base_cryptor_t *)pgs_aead_cryptor_new(&cipher_gcm,
								  key, iv, dir);
	}
	default:
		// not support yet
		break;
	}
	return NULL;
}

void pgs_cryptor_free(pgs_v2ray_secure_t secure, pgs_base_cryptor_t *cryptor)
{
	switch (secure) {
	case V2RAY_SECURE_CFB:
		pgs_aes_cryptor_free((pgs_aes_cryptor_t *)cryptor);
	case V2RAY_SECURE_GCM:
		pgs_aead_cryptor_free((pgs_aead_cryptor_t *)cryptor);
	default:
		// NOTICE: may cause mem leak if hit this branch
		break;
	}
}

// openssl / mbedtls is supported
/* AES */
pgs_aes_cryptor_t *pgs_aes_cryptor_new(const void *cipher, const uint8_t *key,
				       const uint8_t *iv,
				       pgs_cryptor_direction_t dir)
{
	pgs_aes_cryptor_t *ptr = malloc(sizeof(pgs_aes_cryptor_t));
	ptr->key = key;
	ptr->iv = iv;

	ptr->ctx = malloc(sizeof(mbedtls_cipher_context_t));
	mbedtls_cipher_init(ptr->ctx);
	const mbedtls_cipher_info_t *info = mbedtls_cipher_info_from_type(
		*(const mbedtls_cipher_type_t *)cipher);
	// mbedtls_cipher_setup
	if (mbedtls_cipher_setup(ptr->ctx, info)) {
		goto error;
	}
	if (mbedtls_cipher_set_iv(ptr->ctx, iv,
				  mbedtls_cipher_get_iv_size(ptr->ctx))) {
		goto error;
	}

	if (dir == PGS_ENCRYPT) {
		if (mbedtls_cipher_setkey(
			    ptr->ctx, key,
			    mbedtls_cipher_get_key_bitlen(ptr->ctx),
			    MBEDTLS_ENCRYPT)) {
			goto error;
		}
	} else if (dir == PGS_DECRYPT) {
		if (mbedtls_cipher_setkey(
			    ptr->ctx, key,
			    mbedtls_cipher_get_key_bitlen(ptr->ctx),
			    MBEDTLS_DECRYPT)) {
			goto error;
		}
	} else {
		goto error;
	}

	return ptr;

error:

	pgs_aes_cryptor_free(ptr);
	return NULL;
}

void pgs_aes_cryptor_free(pgs_aes_cryptor_t *ptr)
{
	if (ptr->ctx) {
		mbedtls_cipher_free(ptr->ctx);
		free(ptr->ctx);
	}
	free(ptr);
	ptr = NULL;
}

bool pgs_aes_cryptor_encrypt(pgs_aes_cryptor_t *ptr, const uint8_t *plaintext,
			     int plaintext_len, uint8_t *ciphertext)
{
	size_t len;
	if (mbedtls_cipher_update(ptr->ctx, plaintext, plaintext_len,
				  ciphertext, &len)) {
		return false;
	}
	assert(len == plaintext_len);
	return true;
}

bool pgs_aes_cryptor_encrypt_final(pgs_aes_cryptor_t *ptr, uint8_t *ciphertext)
{
	size_t len;
	if (mbedtls_cipher_finish(ptr->ctx, ciphertext, &len)) {
		return false;
	}
	return true;
}

bool pgs_aes_cryptor_decrypt(pgs_aes_cryptor_t *ptr, const uint8_t *ciphertext,
			     int ciphertext_len, uint8_t *plaintext)

{
	size_t len;
	if (mbedtls_cipher_update(ptr->ctx, ciphertext, ciphertext_len,
				  plaintext, &len)) {
		return false;
	}
	return true;
}

bool pgs_aes_cryptor_decrypt_final(pgs_aes_cryptor_t *ptr, uint8_t *plaintext)
{
	size_t len;
	if (mbedtls_cipher_finish(ptr->ctx, plaintext, &len)) {
		return false;
	}
	return true;
}

/* AEAD */
pgs_aead_cryptor_t *pgs_aead_cryptor_new(const void *cipher, const uint8_t *key,
					 const uint8_t *iv,
					 pgs_cryptor_direction_t dir)
{
	pgs_aead_cryptor_t *ptr = malloc(sizeof(pgs_aead_cryptor_t));
	ptr->key = key;
	ptr->counter = 0;
	// vmess using 12 bytes iv aead cipher
	ptr->iv = malloc(sizeof(uint8_t) * 12);
	ptr->dir = dir;
	memzero(ptr->iv, 12);
	memcpy(ptr->iv + 2, iv + 2, 10);

	ptr->ctx = malloc(sizeof(mbedtls_gcm_context));
	mbedtls_gcm_init(ptr->ctx);
	if (mbedtls_gcm_setkey(ptr->ctx, MBEDTLS_CIPHER_ID_AES, key, 128)) {
		goto error;
	}

	return ptr;

error:
	perror("pgs_aead_cryptor_new");
	pgs_aead_cryptor_free(ptr);
	return NULL;
}

void pgs_aead_cryptor_free(pgs_aead_cryptor_t *ptr)
{
	if (ptr->ctx) {
		mbedtls_gcm_free(ptr->ctx);
		free(ptr->ctx);
	}
	if (ptr->iv)
		free(ptr->iv);
	free(ptr);
	ptr = NULL;
}

bool pgs_aead_cryptor_encrypt(pgs_aead_cryptor_t *ptr, const uint8_t *plaintext,
			      int plaintext_len, uint8_t *tag,
			      uint8_t *ciphertext, int *ciphertext_len)
{
	if (mbedtls_gcm_starts(ptr->ctx, MBEDTLS_GCM_ENCRYPT, ptr->iv, 12, NULL,
			       0)) {
		return false;
	}
	if (mbedtls_gcm_update(ptr->ctx, plaintext_len, plaintext,
			       ciphertext)) {
		return false;
	}
	if (mbedtls_gcm_finish(ptr->ctx, tag, 16)) {
		return false;
	}
	*ciphertext_len = plaintext_len;

	// increase iv
	pgs_aead_cryptor_increase_iv(ptr);

	return true;
}

bool pgs_aead_cryptor_decrypt(pgs_aead_cryptor_t *ptr,
			      const uint8_t *ciphertext, int ciphertext_len,
			      const uint8_t *tag, uint8_t *plaintext,
			      int *plaintext_len)
{
	if (mbedtls_gcm_starts(ptr->ctx, MBEDTLS_GCM_DECRYPT, ptr->iv, 12, tag,
			       16)) {
		return false;
	}
	if (mbedtls_gcm_update(ptr->ctx, ciphertext_len, ciphertext,
			       plaintext)) {
		return false;
	}
	*plaintext_len = ciphertext_len;

	pgs_aead_cryptor_increase_iv(ptr);

	return true;
}

void pgs_aead_cryptor_increase_iv(pgs_aead_cryptor_t *ptr)
{
	ptr->counter += 1;
	ptr->iv[0] = ptr->counter >> 8;
	ptr->iv[1] = ptr->counter;
}

// helpers
// returns 1 on success
int rand_bytes(unsigned char *buf, int num)
{
	int i, max, min;
	max = 255;
	min = 0;
	srand(time(0));

	for (i = 0; i < num; ++i)
		buf[i] = (rand() % (max - min + 1)) + min;
	return 1;
}

void sha224(const uint8_t *input, uint64_t input_len, uint8_t *res,
	    uint64_t *res_len)
{
	mbedtls_sha256(input, input_len, res, 1);
	*res_len = 28;
	return;

error:
	perror("error sha224");
	*res_len = 0;
}

void md5(const uint8_t *input, uint64_t input_len, uint8_t *res)
{
	mbedtls_md5_ret(input, input_len, res);
}

void sha1(const uint8_t *input, uint64_t input_len, uint8_t *res)
{
	mbedtls_sha1_ret(input, input_len, res);
}

void hmac_md5(const uint8_t *key, uint64_t key_len, const uint8_t *data,
	      uint64_t data_len, uint8_t *out, uint64_t *out_len)
{
	mbedtls_md_context_t ctx;
	mbedtls_md_init(&ctx);
	const mbedtls_md_info_t *info =
		mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
	mbedtls_md_setup(&ctx, info, 1 /*used hmac*/);
	mbedtls_md_hmac_starts(&ctx, key, key_len);
	mbedtls_md_hmac_update(&ctx, data, data_len);
	mbedtls_md_hmac_finish(&ctx, out);
	mbedtls_md_free(&ctx);
	*out_len = 16;

	assert(*out_len == 16);
}

int aes_128_cfb_encrypt(const uint8_t *plaintext, int plaintext_len,
			const uint8_t *key, const uint8_t *iv,
			uint8_t *ciphertext)
{
	int ciphertext_len;
	size_t len;
	mbedtls_cipher_context_t ctx;
	mbedtls_cipher_init(&ctx);
	const mbedtls_cipher_info_t *info =
		mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CFB128);
	if (mbedtls_cipher_setup(&ctx, info)) {
		goto error;
	}
	if (mbedtls_cipher_set_iv(&ctx, iv, mbedtls_cipher_get_iv_size(&ctx))) {
		goto error;
	}
	if (mbedtls_cipher_setkey(&ctx, key,
				  mbedtls_cipher_get_key_bitlen(&ctx),
				  MBEDTLS_ENCRYPT)) {
		goto error;
	}
	if (mbedtls_cipher_update(&ctx, plaintext, plaintext_len, ciphertext,
				  &len)) {
		goto error;
	}
	ciphertext_len = len;
	if (mbedtls_cipher_finish(&ctx, ciphertext + len, &len)) {
		goto error;
	}
	ciphertext_len += len;
	mbedtls_cipher_free(&ctx);
	return ciphertext_len;

error:
	perror("aes_128_cfb_encrypt");
	return -1;
}

int aes_128_cfb_decrypt(const uint8_t *ciphertext, int ciphertext_len,
			const uint8_t *key, const uint8_t *iv,
			uint8_t *plaintext)
{
	int plaintext_len;
	size_t len;
	mbedtls_cipher_context_t ctx;
	mbedtls_cipher_init(&ctx);
	const mbedtls_cipher_info_t *info =
		mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CFB128);
	if (mbedtls_cipher_setup(&ctx, info)) {
		goto error;
	}
	if (mbedtls_cipher_set_iv(&ctx, iv, mbedtls_cipher_get_iv_size(&ctx))) {
		goto error;
	}
	if (mbedtls_cipher_setkey(&ctx, key,
				  mbedtls_cipher_get_key_bitlen(&ctx),
				  MBEDTLS_DECRYPT)) {
		goto error;
	}
	if (mbedtls_cipher_update(&ctx, ciphertext, ciphertext_len, plaintext,
				  &len)) {
		goto error;
	}
	plaintext_len = len;
	if (mbedtls_cipher_finish(&ctx, plaintext + len, &len)) {
		goto error;
	}
	plaintext_len += len;
	mbedtls_cipher_free(&ctx);
	return plaintext_len;

error:
	perror("aes_128_cfb_decrypt");
	return -1;
}

bool hkdf_sha1(const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
	       size_t ikm_len, const uint8_t *info, size_t info_len,
	       uint8_t *okm, size_t okm_len)
{
	const mbedtls_md_info_t *md =
		mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);

	int ret = mbedtls_hkdf(md, salt, salt_len, ikm, ikm_len, info, info_len,
			       okm, okm_len);
	return ret == 0;
}
