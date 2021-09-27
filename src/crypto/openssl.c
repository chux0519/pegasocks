#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/kdf.h>

static const EVP_CIPHER *get_openssl_cipher(pgs_cryptor_type_t cipher)
{
	switch (cipher) {
	case AES_128_CFB:
		return EVP_aes_128_cfb();
	case AEAD_AES_128_GCM:
		return EVP_aes_128_gcm();
	case AEAD_AES_256_GCM:
		return EVP_aes_256_gcm();
	case AEAD_CHACHA20_POLY1305:
		return EVP_chacha20_poly1305();
	default:
		break;
	}
}

pgs_cryptor_t *pgs_cryptor_new(pgs_cryptor_type_t cipher,
			       pgs_cryptor_direction_t dir, const uint8_t *key,
			       const uint8_t *iv)
{
	pgs_cryptor_t *ptr = malloc(sizeof(pgs_cryptor_t));
	ptr->cipher = cipher;
	ptr->dir = dir;
	ptr->key = key;
	ptr->iv = iv;

	if (!(ptr->ctx = EVP_CIPHER_CTX_new()))
		goto error;

	pgs_cryptor_type_info(cipher, &ptr->key_len, &ptr->iv_len,
			      &ptr->tag_len);

	const EVP_CIPHER *openssl_cipher = get_openssl_cipher(cipher);

	if (openssl_cipher == NULL)
		goto error;

	switch (dir) {
	case PGS_ENCRYPT: {
		if (1 !=
		    EVP_EncryptInit_ex(ptr->ctx, openssl_cipher, NULL, key, iv))
			goto error;
		break;
	}
	case PGS_DECRYPT: {
		if (1 !=
		    EVP_DecryptInit_ex(ptr->ctx, openssl_cipher, NULL, key, iv))
			goto error;
		break;
	}
	default:
		goto error;
	}

	return ptr;

error:
	pgs_cryptor_free(ptr);
	return NULL;
}

void pgs_cryptor_free(pgs_cryptor_t *ptr)
{
	if (ptr->ctx) {
		EVP_CIPHER_CTX_free(ptr->ctx);
	}
	free(ptr);
	ptr = NULL;
}

bool pgs_cryptor_encrypt(pgs_cryptor_t *ptr, const uint8_t *plaintext,
			 size_t plaintext_len, uint8_t *tag,
			 uint8_t *ciphertext, size_t *ciphertext_len)
{
	int len;
	if (1 != EVP_EncryptUpdate(ptr->ctx, ciphertext, &len, plaintext,
				   plaintext_len))
		return false;

	*ciphertext_len = len;

	if (is_aead_cryptor(ptr)) {
		if (1 != EVP_EncryptFinal_ex(ptr->ctx, ciphertext + len, &len))
			return false;
		*ciphertext_len += len;

		if (1 != EVP_CIPHER_CTX_ctrl(ptr->ctx, EVP_CTRL_AEAD_GET_TAG,
					     ptr->tag_len, tag))
			return false;
	}

	return true;
}

bool pgs_cryptor_decrypt(pgs_cryptor_t *ptr, const uint8_t *ciphertext,
			 size_t ciphertext_len, const uint8_t *tag,
			 uint8_t *plaintext, size_t *plaintext_len)
{
	int len = 0;
	if (!EVP_DecryptUpdate(ptr->ctx, plaintext, &len, ciphertext,
			       ciphertext_len))
		return false;
	*plaintext_len = len;

	if (is_aead_cryptor(ptr)) {
		if (!EVP_CIPHER_CTX_ctrl(ptr->ctx, EVP_CTRL_AEAD_SET_TAG,
					 ptr->tag_len, (void *)tag))
			return false;

		if (!EVP_DecryptFinal_ex(ptr->ctx, plaintext + len, &len))
			return false;

		*plaintext_len += len;
	}
	return true;
}

void pgs_cryptor_reset_iv(pgs_cryptor_t *ptr, const uint8_t *iv)
{
	const EVP_CIPHER *openssl_cipher = get_openssl_cipher(ptr->cipher);
	EVP_CIPHER_CTX_reset(ptr->ctx);
	ptr->iv = iv;
	switch (ptr->dir) {
	case PGS_ENCRYPT: {
		EVP_EncryptInit_ex(ptr->ctx, openssl_cipher, NULL, ptr->key,
				   ptr->iv);
		break;
	}
	case PGS_DECRYPT: {
		EVP_DecryptInit_ex(ptr->ctx, openssl_cipher, NULL, ptr->key,
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
