#include "pgs_crypto.h"
#include <assert.h>

pgs_aes_cryptor_t *pgs_aes_cryptor_new(const EVP_CIPHER *cipher,
				       const pgs_buf_t *key,
				       const pgs_buf_t *iv)
{
	pgs_aes_cryptor_t *ptr = pgs_malloc(sizeof(pgs_aes_cryptor_t));
	ptr->key = key;
	ptr->iv = iv;

	if (!(ptr->decrypt_ctx = EVP_CIPHER_CTX_new()))
		goto error;
	if (1 != EVP_DecryptInit_ex(ptr->decrypt_ctx, cipher, NULL, key, iv))
		goto error;

	if (!(ptr->encrypt_ctx = EVP_CIPHER_CTX_new()))
		goto error;
	if (1 != EVP_EncryptInit_ex(ptr->encrypt_ctx, cipher, NULL, key, iv))
		goto error;

	return ptr;

error:
	perror("pgs_aes_cryptor_new");
	return NULL;
}

void pgs_aes_cryptor_free(pgs_aes_cryptor_t *ptr)
{
	EVP_CIPHER_CTX_free(ptr->encrypt_ctx);
	EVP_CIPHER_CTX_free(ptr->decrypt_ctx);
	pgs_free(ptr);
	ptr = NULL;
}

bool pgs_aes_cryptor_encrypt(pgs_aes_cryptor_t *ptr, const pgs_buf_t *plaintext,
			     int plaintext_len, pgs_buf_t *ciphertext)
{
	int len = 0;
	if (1 != EVP_EncryptUpdate(ptr->encrypt_ctx, ciphertext, &len,
				   plaintext, plaintext_len))
		return false;
	assert(len == plaintext_len);
	return true;
}

bool pgs_aes_cryptor_encrypt_final(pgs_aes_cryptor_t *ptr,
				   const pgs_buf_t *plaintext,
				   int plaintext_len, pgs_buf_t *ciphertext)
{
	int len = 0;
	if (1 != EVP_EncryptFinal_ex(ptr->encrypt_ctx, ciphertext, &len))
		return false;
	return true;
}

bool pgs_aes_cryptor_decrypt(pgs_aes_cryptor_t *ptr,
			     const pgs_buf_t *ciphertext, int ciphertext_len,
			     pgs_buf_t *plaintext)
{
	int len = 0;
	if (1 != EVP_DecryptUpdate(ptr->decrypt_ctx, plaintext, &len,
				   ciphertext, ciphertext_len))
		return false;

	return true;
}

bool pgs_aes_cryptor_decrypt_final(pgs_aes_cryptor_t *ptr,
				   const pgs_buf_t *ciphertext,
				   int ciphertext_len, pgs_buf_t *plaintext)
{
	int len = 0;
	if (1 != EVP_DecryptFinal_ex(ptr->decrypt_ctx, plaintext, &len))
		return false;
	return true;
}

