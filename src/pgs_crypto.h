#ifndef _PGS_CRYPTO
#define _PGS_CRYPTO

#include "pgs_core.h"
#include <openssl/evp.h>

typedef struct pgs_aes_cryptor_s pgs_aes_cryptor_t;

struct pgs_aes_cryptor_s {
	EVP_CIPHER_CTX *encrypt_ctx;
	EVP_CIPHER_CTX *decrypt_ctx;
	const pgs_buf_t *key;
	const pgs_buf_t *iv;
};

pgs_aes_cryptor_t *pgs_aes_cryptor_new(const EVP_CIPHER *cipher,
				       const pgs_buf_t *key,
				       const pgs_buf_t *iv);
void pgs_aes_cryptor_free(pgs_aes_cryptor_t *ptr);
bool pgs_aes_cryptor_encrypt(pgs_aes_cryptor_t *ptr, const pgs_buf_t *plaintext,
			     int plaintext_len, pgs_buf_t *ciphertext);
bool pgs_aes_cryptor_encrypt_final(pgs_aes_cryptor_t *ptr,
				   const pgs_buf_t *plaintext,
				   int plaintext_len, pgs_buf_t *ciphertext);
bool pgs_aes_cryptor_decrypt(pgs_aes_cryptor_t *ptr,
			     const pgs_buf_t *ciphertext, int ciphertext_len,
			     pgs_buf_t *plaintext);
bool pgs_aes_cryptor_decrypt_final(pgs_aes_cryptor_t *ptr,
				   const pgs_buf_t *ciphertext,
				   int ciphertext_len, pgs_buf_t *plaintext);

#endif
