#include "core/crypto.h"

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/kdf.h>

pgs_base_cryptor_t *pgs_cryptor_new(pgs_v2ray_secure_t secure,
				    const uint8_t *key, const uint8_t *iv,
				    pgs_cryptor_direction_t dir)
{
	switch (secure) {
	case V2RAY_SECURE_CFB: {
		const EVP_CIPHER *cipher_cfb = EVP_aes_128_cfb();
		return pgs_aes_cryptor_new(cipher_cfb, key, iv, dir);
	}
	case V2RAY_SECURE_GCM: {
		const EVP_CIPHER *cipher_gcm = EVP_aes_128_gcm();
		return (pgs_base_cryptor_t *)pgs_aead_cryptor_new(cipher_gcm,
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
		return pgs_aes_cryptor_free((pgs_aes_cryptor_t *)cryptor);
	case V2RAY_SECURE_GCM:
		return pgs_aead_cryptor_free((pgs_aead_cryptor_t *)cryptor);
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

	return ptr;

error:

	pgs_aes_cryptor_free(ptr);
	return NULL;
}

void pgs_aes_cryptor_free(pgs_aes_cryptor_t *ptr)
{
	if (ptr->ctx) {
		EVP_CIPHER_CTX_free(ptr->ctx);
	}
	free(ptr);
	ptr = NULL;
}

bool pgs_aes_cryptor_encrypt(pgs_aes_cryptor_t *ptr, const uint8_t *plaintext,
			     int plaintext_len, uint8_t *ciphertext)
{
	int len = 0;
	if (1 != EVP_EncryptUpdate(ptr->ctx, ciphertext, &len, plaintext,
				   plaintext_len))
		return false;
	assert(len == plaintext_len);
	return true;
}

bool pgs_aes_cryptor_encrypt_final(pgs_aes_cryptor_t *ptr, uint8_t *ciphertext)
{
	int len = 0;
	if (1 != EVP_EncryptFinal_ex(ptr->ctx, ciphertext, &len))
		return false;
	return true;
}

bool pgs_aes_cryptor_decrypt(pgs_aes_cryptor_t *ptr, const uint8_t *ciphertext,
			     int ciphertext_len, uint8_t *plaintext)

{
	int len = 0;
	if (1 != EVP_DecryptUpdate(ptr->ctx, plaintext, &len, ciphertext,
				   ciphertext_len))
		return false;
	return true;
}

bool pgs_aes_cryptor_decrypt_final(pgs_aes_cryptor_t *ptr, uint8_t *plaintext)
{
	int len = 0;
	if (1 != EVP_DecryptFinal_ex(ptr->ctx, plaintext, &len))
		return false;
	return true;
}

/* AEAD */
pgs_aead_cryptor_t *pgs_aead_cryptor_new(const void *cipher, const uint8_t *key,
					 const uint8_t *iv,
					 pgs_cryptor_direction_t dir)
{
	pgs_aead_cryptor_t *ptr = malloc(sizeof(pgs_aead_cryptor_t));
	// TODO: vmess chacha key
	ptr->key = key;
	ptr->counter = 0;
	// vmess using 12 bytes iv aead cipher
	ptr->iv = malloc(sizeof(uint8_t) * 12);
	ptr->dir = dir;
	memzero(ptr->iv, 12);
	memcpy(ptr->iv + 2, iv + 2, 10);

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

	return ptr;

error:
	perror("pgs_aead_cryptor_new");
	pgs_aead_cryptor_free(ptr);
	return NULL;
}

void pgs_aead_cryptor_free(pgs_aead_cryptor_t *ptr)
{
	if (ptr->ctx) {
		EVP_CIPHER_CTX_free(ptr->ctx);
		ptr->ctx = NULL;
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

	// increase iv
	pgs_aead_cryptor_increase_iv(ptr);

	return true;
}

bool pgs_aead_cryptor_decrypt(pgs_aead_cryptor_t *ptr,
			      const uint8_t *ciphertext, int ciphertext_len,
			      const uint8_t *tag, uint8_t *plaintext,
			      int *plaintext_len)
{
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

	pgs_aead_cryptor_increase_iv(ptr);

	return true;
}

void pgs_aead_cryptor_increase_iv(pgs_aead_cryptor_t *ptr)
{
	ptr->counter += 1;
	ptr->iv[0] = ptr->counter >> 8;
	ptr->iv[1] = ptr->counter;

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
}

// helpers
// returns 1 on success
int rand_bytes(unsigned char *buf, int num)
{
	return RAND_bytes(buf, num);
}

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

void md5(const uint8_t *input, uint64_t input_len, uint8_t *res)
{
	MD5(input, input_len, res);
}

void sha1(const uint8_t *input, uint64_t input_len, uint8_t *res)
{
	SHA1(input, input_len, res);
}

void hmac_md5(const uint8_t *key, uint64_t key_len, const uint8_t *data,
	      uint64_t data_len, uint8_t *out, uint64_t *out_len)
{
	HMAC(EVP_md5(), key, key_len, data, data_len, out,
	     (unsigned int *)out_len);
	assert(*out_len == 16);
}

int aes_128_cfb_encrypt(const uint8_t *plaintext, int plaintext_len,
			const uint8_t *key, const uint8_t *iv,
			uint8_t *ciphertext)
{
	int ciphertext_len;
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

	return plaintext_len;

error:
	perror("aes_128_cfb_decrypt");
	return -1;
}

bool hkdf_sha1(const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
	       size_t ikm_len, const uint8_t *info, size_t info_len,
	       uint8_t *okm, size_t okm_len)

{
	size_t outlen = okm_len;
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

	if (EVP_PKEY_derive_init(pctx) <= 0)
		goto error;
	if (EVP_PKEY_CTX_hkdf_mode(pctx,
				   EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) <= 0)
		goto error;
	if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha1()) <= 0)
		goto error;
	if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) <= 0)
		goto error;
	if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, ikm_len) <= 0)
		goto error;
	if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) <= 0)
		goto error;
	if (EVP_PKEY_derive(pctx, okm, &outlen) <= 0)
		goto error;

	assert(outlen == okm_len);
	EVP_PKEY_CTX_free(pctx);
	return true;
error:
	return false;
}
