#include "crypto.h"

#include <stdlib.h>
#include <time.h>
#include <mbedtls/cipher.h>
#include <mbedtls/gcm.h>
#include <mbedtls/chachapoly.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md5.h>
#include <mbedtls/sha1.h>
#include <mbedtls/md.h>
#include <mbedtls/hkdf.h>

static const mbedtls_cipher_type_t
get_mbedtls_cipher(pgs_cryptor_type_t cipher);

static bool pgs_cryptor_init_aes(pgs_cryptor_t *ptr);
static bool pgs_cryptor_encrypt_aes(pgs_cryptor_t *ptr,
				    const uint8_t *plaintext,
				    size_t plaintext_len, uint8_t *tag,
				    uint8_t *ciphertext,
				    size_t *ciphertext_len);
static bool pgs_cryptor_decrypt_aes(pgs_cryptor_t *ptr,
				    const uint8_t *ciphertext,
				    size_t ciphertext_len, const uint8_t *tag,
				    uint8_t *plaintext, size_t *plaintext_len);

static bool pgs_cryptor_init_gcm(pgs_cryptor_t *ptr);
static bool pgs_cryptor_encrypt_gcm(pgs_cryptor_t *ptr,
				    const uint8_t *plaintext,
				    size_t plaintext_len, uint8_t *tag,
				    uint8_t *ciphertext,
				    size_t *ciphertext_len);
static bool pgs_cryptor_decrypt_gcm(pgs_cryptor_t *ptr,
				    const uint8_t *ciphertext,
				    size_t ciphertext_len, const uint8_t *tag,
				    uint8_t *plaintext, size_t *plaintext_len);

static bool pgs_cryptor_init_chachapoly(pgs_cryptor_t *ptr);
static bool pgs_cryptor_encrypt_chachapoly(pgs_cryptor_t *ptr,
					   const uint8_t *plaintext,
					   size_t plaintext_len, uint8_t *tag,
					   uint8_t *ciphertext,
					   size_t *ciphertext_len);
static bool
pgs_cryptor_decrypt_chachapoly(pgs_cryptor_t *ptr, const uint8_t *ciphertext,
			       size_t ciphertext_len, const uint8_t *tag,
			       uint8_t *plaintext, size_t *plaintext_len);

pgs_cryptor_t *pgs_cryptor_new(pgs_cryptor_type_t cipher,
			       pgs_cryptor_direction_t dir, const uint8_t *key,
			       const uint8_t *iv)
{
	pgs_cryptor_t *ptr = malloc(sizeof(pgs_cryptor_t));
	ptr->cipher = cipher;
	ptr->dir = dir;
	ptr->key = key;
	ptr->iv = iv;
	pgs_cryptor_type_info(cipher, &ptr->key_len, &ptr->iv_len,
			      &ptr->tag_len);

	switch (ptr->cipher) {
	case AES_128_CFB:
		if (!pgs_cryptor_init_aes(ptr)) {
			goto error;
		}
		break;
	case AEAD_AES_128_GCM:
	case AEAD_AES_256_GCM:
		if (!pgs_cryptor_init_gcm(ptr)) {
			goto error;
		}
		break;
	case AEAD_CHACHA20_POLY1305:
		if (!pgs_cryptor_init_chachapoly(ptr)) {
			goto error;
		}
		break;
	default:
		break;
	}

	return ptr;

error:
	perror("pgs_cryptor_new");
	pgs_cryptor_free(ptr);
	return NULL;
}

void pgs_cryptor_free(pgs_cryptor_t *ptr)
{
	switch (ptr->cipher) {
	case AES_128_CFB:
		if (ptr->ctx) {
			mbedtls_cipher_free(ptr->ctx);
			free(ptr->ctx);
		}
		break;
	case AEAD_AES_128_GCM:
	case AEAD_AES_256_GCM:
		if (ptr->ctx) {
			mbedtls_gcm_free(ptr->ctx);
			free(ptr->ctx);
		}
		break;
	case AEAD_CHACHA20_POLY1305:
		if (ptr->ctx) {
			mbedtls_chachapoly_free(ptr->ctx);
			free(ptr->ctx);
		}
		break;
	default:
		break;
	}

	free(ptr);
	ptr = NULL;
}

bool pgs_cryptor_encrypt(pgs_cryptor_t *ptr, const uint8_t *plaintext,
			 size_t plaintext_len, uint8_t *tag,
			 uint8_t *ciphertext, size_t *ciphertext_len)
{
	switch (ptr->cipher) {
	case AES_128_CFB:
		return pgs_cryptor_encrypt_aes(ptr, plaintext, plaintext_len,
					       tag, ciphertext, ciphertext_len);
	case AEAD_AES_128_GCM:
	case AEAD_AES_256_GCM:
		return pgs_cryptor_encrypt_gcm(ptr, plaintext, plaintext_len,
					       tag, ciphertext, ciphertext_len);
	case AEAD_CHACHA20_POLY1305:
		return pgs_cryptor_encrypt_chachapoly(ptr, plaintext,
						      plaintext_len, tag,
						      ciphertext,
						      ciphertext_len);
	default:
		break;
	}
	return false;
}

bool pgs_cryptor_decrypt(pgs_cryptor_t *ptr, const uint8_t *ciphertext,
			 size_t ciphertext_len, const uint8_t *tag,
			 uint8_t *plaintext, size_t *plaintext_len)
{
	switch (ptr->cipher) {
	case AES_128_CFB:
		return pgs_cryptor_decrypt_aes(ptr, ciphertext, ciphertext_len,
					       tag, plaintext, plaintext_len);
	case AEAD_AES_128_GCM:
	case AEAD_AES_256_GCM:
		return pgs_cryptor_decrypt_gcm(ptr, ciphertext, ciphertext_len,
					       tag, plaintext, plaintext_len);
	case AEAD_CHACHA20_POLY1305:
		return pgs_cryptor_decrypt_chachapoly(ptr, ciphertext,
						      ciphertext_len, tag,
						      plaintext, plaintext_len);
	default:
		break;
	}
	return false;
}

void pgs_cryptor_reset_iv(pgs_cryptor_t *ptr, const uint8_t *iv)
{
	// nothing to do
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

// ===================== static
static const mbedtls_cipher_type_t get_mbedtls_cipher(pgs_cryptor_type_t cipher)
{
	switch (cipher) {
	case AES_128_CFB:
		return MBEDTLS_CIPHER_AES_128_CFB128;
	case AEAD_AES_128_GCM:
		return MBEDTLS_CIPHER_AES_128_GCM;
	case AEAD_AES_256_GCM:
		return MBEDTLS_CIPHER_AES_256_GCM;
	case AEAD_CHACHA20_POLY1305:
		return MBEDTLS_CIPHER_CHACHA20_POLY1305;
	default:
		break;
	}
}

static bool pgs_cryptor_init_aes(pgs_cryptor_t *ptr)
{
	ptr->ctx = malloc(sizeof(mbedtls_cipher_context_t));
	mbedtls_cipher_init(ptr->ctx);

	pgs_cryptor_type_info(ptr->cipher, &ptr->key_len, &ptr->iv_len,
			      &ptr->tag_len);

	const mbedtls_cipher_type_t mbedtls_cipher =
		get_mbedtls_cipher(ptr->cipher);
	const mbedtls_cipher_info_t *info =
		mbedtls_cipher_info_from_type(mbedtls_cipher);

	if (mbedtls_cipher_setup(ptr->ctx, info)) {
		return false;
	}

	assert(mbedtls_cipher_get_iv_size(ptr->ctx) == ptr->iv_len);
	if (mbedtls_cipher_set_iv(ptr->ctx, ptr->iv,
				  mbedtls_cipher_get_iv_size(ptr->ctx))) {
		return false;
	}

	assert(mbedtls_cipher_get_key_bitlen(ptr->ctx) == ptr->key_len * 8);
	if (ptr->dir == PGS_ENCRYPT) {
		if (mbedtls_cipher_setkey(
			    ptr->ctx, ptr->key,
			    mbedtls_cipher_get_key_bitlen(ptr->ctx),
			    MBEDTLS_ENCRYPT)) {
			return false;
		}
	} else if (ptr->dir == PGS_DECRYPT) {
		if (mbedtls_cipher_setkey(
			    ptr->ctx, ptr->key,
			    mbedtls_cipher_get_key_bitlen(ptr->ctx),
			    MBEDTLS_DECRYPT)) {
			return false;
		}
	} else {
		return false;
	}
	return true;
}

static bool pgs_cryptor_init_gcm(pgs_cryptor_t *ptr)
{
	ptr->ctx = malloc(sizeof(mbedtls_gcm_context));
	mbedtls_gcm_init(ptr->ctx);
	if (mbedtls_gcm_setkey(ptr->ctx, MBEDTLS_CIPHER_ID_AES, ptr->key,
			       8 * ptr->key_len)) {
		return false;
	}
	return true;
}

static bool pgs_cryptor_init_chachapoly(pgs_cryptor_t *ptr)
{
	ptr->ctx = malloc(sizeof(mbedtls_chachapoly_context));
	mbedtls_chachapoly_init(ptr->ctx);
	if (mbedtls_chachapoly_setkey(ptr->ctx, ptr->key)) {
		return false;
	}
	return true;
}

static bool pgs_cryptor_encrypt_aes(pgs_cryptor_t *ptr,
				    const uint8_t *plaintext,
				    size_t plaintext_len, uint8_t *tag,
				    uint8_t *ciphertext, size_t *ciphertext_len)
{
	size_t len;
	if (mbedtls_cipher_update(ptr->ctx, plaintext, plaintext_len,
				  ciphertext, &len)) {
		return false;
	}
	*ciphertext_len = len;
	return true;
}
static bool pgs_cryptor_decrypt_aes(pgs_cryptor_t *ptr,
				    const uint8_t *ciphertext,
				    size_t ciphertext_len, const uint8_t *tag,
				    uint8_t *plaintext, size_t *plaintext_len)
{
	size_t len;
	if (mbedtls_cipher_update(ptr->ctx, ciphertext, ciphertext_len,
				  plaintext, &len)) {
		return false;
	}
	*plaintext_len = len;

	return true;
}

static bool pgs_cryptor_encrypt_gcm(pgs_cryptor_t *ptr,
				    const uint8_t *plaintext,
				    size_t plaintext_len, uint8_t *tag,
				    uint8_t *ciphertext, size_t *ciphertext_len)
{
	if (mbedtls_gcm_starts(ptr->ctx, MBEDTLS_GCM_ENCRYPT, ptr->iv,
			       ptr->iv_len, NULL, 0)) {
		return false;
	}
	if (mbedtls_gcm_update(ptr->ctx, plaintext_len, plaintext,
			       ciphertext)) {
		return false;
	}
	if (mbedtls_gcm_finish(ptr->ctx, tag, ptr->tag_len)) {
		return false;
	}
	*ciphertext_len = plaintext_len;
	return true;
}

static bool pgs_cryptor_decrypt_gcm(pgs_cryptor_t *ptr,
				    const uint8_t *ciphertext,
				    size_t ciphertext_len, const uint8_t *tag,
				    uint8_t *plaintext, size_t *plaintext_len)
{
	if (mbedtls_gcm_starts(ptr->ctx, MBEDTLS_GCM_DECRYPT, ptr->iv,
			       ptr->iv_len, tag, ptr->tag_len)) {
		return false;
	}
	if (mbedtls_gcm_update(ptr->ctx, ciphertext_len, ciphertext,
			       plaintext)) {
		return false;
	}
	*plaintext_len = ciphertext_len;

	return true;
}

static bool pgs_cryptor_encrypt_chachapoly(pgs_cryptor_t *ptr,
					   const uint8_t *plaintext,
					   size_t plaintext_len, uint8_t *tag,
					   uint8_t *ciphertext,
					   size_t *ciphertext_len)
{
	if (mbedtls_chachapoly_starts(ptr->ctx, ptr->iv,
				      MBEDTLS_CHACHAPOLY_ENCRYPT)) {
		return false;
	}
	if (mbedtls_chachapoly_update(ptr->ctx, plaintext_len, plaintext,
				      ciphertext)) {
		return false;
	}
	if (mbedtls_chachapoly_finish(ptr->ctx, tag)) {
		return false;
	}
	*ciphertext_len = plaintext_len;
	return true;
}

static bool
pgs_cryptor_decrypt_chachapoly(pgs_cryptor_t *ptr, const uint8_t *ciphertext,
			       size_t ciphertext_len, const uint8_t *tag,
			       uint8_t *plaintext, size_t *plaintext_len)
{
	int ret = mbedtls_chachapoly_auth_decrypt(ptr->ctx, ciphertext_len,
						  ptr->iv, NULL, 0, tag,
						  ciphertext, plaintext);
	*plaintext_len = ciphertext_len;
	return ret == 0;
}
