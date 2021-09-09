#include "pgs_crypto.h"
#include <assert.h>

/* AES */
pgs_aes_cryptor_t *pgs_aes_cryptor_new(const EVP_CIPHER *cipher,
				       const uint8_t *key, const uint8_t *iv,
				       pgs_cryptor_direction_t dir)
{
	pgs_aes_cryptor_t *ptr = malloc(sizeof(pgs_aes_cryptor_t));
	ptr->key = key;
	ptr->iv = iv;

	switch (dir) {
	case PGS_ENCRYPT: {
		if (!(ptr->ctx = EVP_CIPHER_CTX_new()))
			goto error;
		if (1 != EVP_EncryptInit_ex(ptr->ctx, cipher, NULL, key, iv))
			goto error;
		break;
	}
	case PGS_DECRYPT: {
		if (!(ptr->ctx = EVP_CIPHER_CTX_new()))
			goto error;
		if (1 != EVP_DecryptInit_ex(ptr->ctx, cipher, NULL, key, iv))
			goto error;

		break;
	}
	default:
		goto error;
	}

	return ptr;

error:
	perror("pgs_aes_cryptor_new");
	pgs_aes_cryptor_free(ptr);
	return NULL;
}

void pgs_aes_cryptor_free(pgs_aes_cryptor_t *ptr)
{
	if (ptr->ctx)
		EVP_CIPHER_CTX_free(ptr->ctx);
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

bool pgs_aes_cryptor_encrypt_final(pgs_aes_cryptor_t *ptr,
				   const uint8_t *plaintext, int plaintext_len,
				   uint8_t *ciphertext)
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

bool pgs_aes_cryptor_decrypt_final(pgs_aes_cryptor_t *ptr,
				   const uint8_t *ciphertext,
				   int ciphertext_len, uint8_t *plaintext)
{
	int len = 0;
	if (1 != EVP_DecryptFinal_ex(ptr->ctx, plaintext, &len))
		return false;
	return true;
}

/* AEAD */
pgs_aead_cryptor_t *pgs_aead_cryptor_new(const EVP_CIPHER *cipher,
					 const uint8_t *key, const uint8_t *iv,
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
	if (ptr->ctx)
		EVP_CIPHER_CTX_free(ptr->ctx);
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
