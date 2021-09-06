#include "pgs_crypto.h"
#include <assert.h>

#ifdef USE_MBEDTLS
#include <stdlib.h>
#include <time.h>
#include <mbedtls/cipher.h>
#include <mbedtls/gcm.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md5.h>
#include <mbedtls/md.h>
#else
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#endif

pgs_base_cryptor_t *pgs_cryptor_new(pgs_v2ray_secure_t secure,
				    const uint8_t *key, const uint8_t *iv,
				    pgs_cryptor_direction_t dir)
{
	switch (secure) {
	case V2RAY_SECURE_CFB: {
#ifdef USE_MBEDTLS
		mbedtls_cipher_type_t cipher_cfb =
			MBEDTLS_CIPHER_AES_128_CFB128;
		return pgs_aes_cryptor_new(&cipher_cfb, key, iv, dir);
#else
		const EVP_CIPHER *cipher_cfb = EVP_aes_128_cfb();
		return pgs_aes_cryptor_new(cipher_cfb, key, iv, dir);
#endif
	}
	case V2RAY_SECURE_GCM: {
#ifdef USE_MBEDTLS
		mbedtls_cipher_type_t cipher_gcm = MBEDTLS_CIPHER_AES_128_GCM;
		return (pgs_base_cryptor_t *)pgs_aead_cryptor_new(&cipher_gcm,
								  key, iv, dir);
#else
		const EVP_CIPHER *cipher_gcm = EVP_aes_128_gcm();
		return (pgs_base_cryptor_t *)pgs_aead_cryptor_new(cipher_gcm,
								  key, iv, dir);
#endif
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

#ifdef USE_MBEDTLS
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

#else
	if (!(ptr->ctx = EVP_CIPHER_CTX_new()))
		goto error;
	switch (dir) {
	case PGS_ENCRYPT: {
		if (1 != EVP_EncryptInit_ex(ptr->ctx,
					    (const EVP_CIPHER *)cipher, NULL,
					    key, iv))
			goto error;
		break;
	}
	case PGS_DECRYPT: {
		if (1 != EVP_DecryptInit_ex(ptr->ctx,
					    (const EVP_CIPHER *)cipher, NULL,
					    key, iv))
			goto error;
		break;
	}
	default:
		goto error;
	}
#endif

	return ptr;

error:

	pgs_aes_cryptor_free(ptr);
	return NULL;
}

void pgs_aes_cryptor_free(pgs_aes_cryptor_t *ptr)
{
	if (ptr->ctx) {
#ifdef USE_MBEDTLS
		mbedtls_cipher_free(ptr->ctx);
		free(ptr->ctx);
#else
		EVP_CIPHER_CTX_free(ptr->ctx);
#endif
	}
	free(ptr);
	ptr = NULL;
}

bool pgs_aes_cryptor_encrypt(pgs_aes_cryptor_t *ptr, const uint8_t *plaintext,
			     int plaintext_len, uint8_t *ciphertext)
{
#ifdef USE_MBEDTLS
	size_t len;
	if (mbedtls_cipher_update(ptr->ctx, plaintext, plaintext_len,
				  ciphertext, &len)) {
		return false;
	}
	assert(len == plaintext_len);
#else
	int len = 0;
	if (1 != EVP_EncryptUpdate(ptr->ctx, ciphertext, &len, plaintext,
				   plaintext_len))
		return false;
	assert(len == plaintext_len);
#endif
	return true;
}

bool pgs_aes_cryptor_encrypt_final(pgs_aes_cryptor_t *ptr, uint8_t *ciphertext)
{
#ifdef USE_MBEDTLS
	size_t len;
	if (mbedtls_cipher_finish(ptr->ctx, ciphertext, &len)) {
		return false;
	}
#else
	int len = 0;
	if (1 != EVP_EncryptFinal_ex(ptr->ctx, ciphertext, &len))
		return false;
#endif
	return true;
}

bool pgs_aes_cryptor_decrypt(pgs_aes_cryptor_t *ptr, const uint8_t *ciphertext,
			     int ciphertext_len, uint8_t *plaintext)

{
#ifdef USE_MBEDTLS
	size_t len;
	if (mbedtls_cipher_update(ptr->ctx, ciphertext, ciphertext_len,
				  plaintext, &len)) {
		return false;
	}
#else
	int len = 0;
	if (1 != EVP_DecryptUpdate(ptr->ctx, plaintext, &len, ciphertext,
				   ciphertext_len))
		return false;
#endif
	return true;
}

bool pgs_aes_cryptor_decrypt_final(pgs_aes_cryptor_t *ptr, uint8_t *plaintext)
{
#ifdef USE_MBEDTLS
	size_t len;
	if (mbedtls_cipher_finish(ptr->ctx, plaintext, &len)) {
		return false;
	}
#else
	int len = 0;
	if (1 != EVP_DecryptFinal_ex(ptr->ctx, plaintext, &len))
		return false;
#endif
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

#ifdef USE_MBEDTLS
	ptr->ctx = malloc(sizeof(mbedtls_gcm_context));
	mbedtls_gcm_init(ptr->ctx);
	if (mbedtls_gcm_setkey(ptr->ctx, MBEDTLS_CIPHER_ID_AES, key, 128)) {
		goto error;
	}

#else
	switch (dir) {
	case PGS_ENCRYPT: {
		if (!(ptr->ctx = EVP_CIPHER_CTX_new()))
			goto error;
		if (1 != EVP_EncryptInit_ex(ptr->ctx, EVP_aes_128_gcm(), NULL,
					    ptr->key, ptr->iv))
			goto error;

		break;
	}
	case PGS_DECRYPT: {
		if (!(ptr->ctx = EVP_CIPHER_CTX_new()))
			goto error;
		if (1 != EVP_DecryptInit_ex(ptr->ctx, EVP_aes_128_gcm(), NULL,
					    ptr->key, ptr->iv))
			goto error;

		break;
	}
	default:
		goto error;
	}
#endif

	return ptr;

error:
	perror("pgs_aead_cryptor_new");
	pgs_aead_cryptor_free(ptr);
	return NULL;
}

void pgs_aead_cryptor_free(pgs_aead_cryptor_t *ptr)
{
	if (ptr->ctx) {
#ifdef USE_MBEDTLS
		mbedtls_gcm_free(ptr->ctx);
		free(ptr->ctx);
#else
		EVP_CIPHER_CTX_free(ptr->ctx);
#endif
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
#ifdef USE_MBEDTLS
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
#else
	int len;
	if (1 != EVP_EncryptUpdate(ptr->ctx, ciphertext, &len, plaintext,
				   plaintext_len))
		return false;
	*ciphertext_len = len;

	if (1 != EVP_EncryptFinal_ex(ptr->ctx, ciphertext + len, &len))
		return false;
	*ciphertext_len += len;

	if (1 != EVP_CIPHER_CTX_ctrl(ptr->ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
		return false;
#endif

	// increase iv
	pgs_aead_cryptor_increase_iv(ptr);

	return true;
}

bool pgs_aead_cryptor_decrypt(pgs_aead_cryptor_t *ptr,
			      const uint8_t *ciphertext, int ciphertext_len,
			      const uint8_t *tag, uint8_t *plaintext,
			      int *plaintext_len)
{
#ifdef USE_MBEDTLS
	if (mbedtls_gcm_starts(ptr->ctx, MBEDTLS_GCM_DECRYPT, ptr->iv, 12, tag,
			       16)) {
		return false;
	}
	if (mbedtls_gcm_update(ptr->ctx, ciphertext_len, ciphertext,
			       plaintext)) {
		return false;
	}
	*plaintext_len = ciphertext_len;

#else
	int len = 0;
	if (!EVP_DecryptUpdate(ptr->ctx, plaintext, &len, ciphertext,
			       ciphertext_len))
		return false;
	*plaintext_len = len;

	if (!EVP_CIPHER_CTX_ctrl(ptr->ctx, EVP_CTRL_GCM_SET_TAG, 16,
				 (void *)tag))
		return false;

	if (!EVP_DecryptFinal_ex(ptr->ctx, plaintext + len, &len))
		return false;

	*plaintext_len += len;
#endif

	pgs_aead_cryptor_increase_iv(ptr);

	return true;
}

void pgs_aead_cryptor_increase_iv(pgs_aead_cryptor_t *ptr)
{
	ptr->counter += 1;
	ptr->iv[0] = ptr->counter >> 8;
	ptr->iv[1] = ptr->counter;

#ifdef USE_MBEDTLS
	// nothing to do
#else
	EVP_CIPHER_CTX_reset(ptr->ctx);
	switch (ptr->dir) {
	case PGS_ENCRYPT: {
		EVP_EncryptInit_ex(ptr->ctx, EVP_aes_128_gcm(), NULL, ptr->key,
				   ptr->iv);
		break;
	}
	case PGS_DECRYPT: {
		EVP_DecryptInit_ex(ptr->ctx, EVP_aes_128_gcm(), NULL, ptr->key,
				   ptr->iv);
		break;
	}
	default:
		break;
	}
#endif
}

// helpers
// returns 1 on success
int rand_bytes(unsigned char *buf, int num)
{
#ifdef USE_MBEDTLS
	int i, max, min;
	max = 255;
	min = 0;
	srand(time(0));

	for (i = 0; i < num; ++i)
		buf[i] = (rand() % (max - min + 1)) + min;
	return 1;
#else
	return RAND_bytes(buf, num);
#endif
}

void sha224(const uint8_t *input, uint64_t input_len, uint8_t *res,
	    uint64_t *res_len)
{
#ifdef USE_MBEDTLS
	mbedtls_sha256(input, input_len, res, 1);
	*res_len = 28;
#else
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
#endif
	return;

error:
	perror("error sha224");
#ifdef USE_MBEDTLS
#else
	if (ctx != NULL)
		EVP_MD_CTX_free(ctx);
#endif
	*res_len = 0;
}

void md5(const uint8_t *input, uint64_t input_len, uint8_t *res)
{
#ifdef USE_MBEDTLS
	mbedtls_md5_ret(input, input_len, res);
#else
	MD5(input, input_len, res);
#endif
}

void hmac_md5(const uint8_t *key, uint64_t key_len, const uint8_t *data,
	      uint64_t data_len, uint8_t *out, uint64_t *out_len)
{
#ifdef USE_MBEDTLS
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
#else
	HMAC(EVP_md5(), key, key_len, data, data_len, out,
	     (unsigned int *)out_len);
#endif
	assert(*out_len == 16);
}

int aes_128_cfb_encrypt(const uint8_t *plaintext, int plaintext_len,
			const uint8_t *key, const uint8_t *iv,
			uint8_t *ciphertext)
{
	int ciphertext_len;
#ifdef USE_MBEDTLS
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
#else
	int len;
	EVP_CIPHER_CTX *ctx;
	if (!(ctx = EVP_CIPHER_CTX_new()))
		goto error;

	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, key, iv))
		goto error;

	if (1 !=
	    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		goto error;
	ciphertext_len = len;

	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		goto error;
	ciphertext_len += len;

	EVP_CIPHER_CTX_free(ctx);
#endif

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
#ifdef USE_MBEDTLS
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
#else
	int len;
	EVP_CIPHER_CTX *ctx;
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

	EVP_CIPHER_CTX_free(ctx);
#endif

	return plaintext_len;

error:
	perror("aes_128_cfb_decrypt");
	return -1;
}
