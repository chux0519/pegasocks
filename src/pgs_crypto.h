#ifndef _PGS_CRYPTO
#define _PGS_CRYPTO

#include "pgs_core.h"
#include <openssl/evp.h>

typedef struct pgs_base_cryptor_s pgs_base_cryptor_t;
typedef struct pgs_base_cryptor_s pgs_aes_cryptor_t;
typedef struct pgs_aead_cryptor_s pgs_aead_cryptor_t;
typedef enum { PGS_ENCRYPT, PGS_DECRYPT } pgs_cryptor_direction_t;

struct pgs_base_cryptor_s {
	EVP_CIPHER_CTX *ctx;
	const pgs_buf_t *key;
	const pgs_buf_t *iv;
};

struct pgs_aead_cryptor_s {
	EVP_CIPHER_CTX *ctx;
	const pgs_buf_t *key;
	pgs_buf_t *iv;
	pgs_cryptor_direction_t dir;
	uint16_t counter;
};

/* AES cipher */
pgs_aes_cryptor_t *pgs_aes_cryptor_new(const EVP_CIPHER *cipher,
				       const pgs_buf_t *key,
				       const pgs_buf_t *iv,
				       pgs_cryptor_direction_t dir);
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

/* AEAD cipher */
pgs_aead_cryptor_t *pgs_aead_cryptor_new(const EVP_CIPHER *cipher,
					 const pgs_buf_t *key,
					 const pgs_buf_t *iv,
					 pgs_cryptor_direction_t dir);
void pgs_aead_cryptor_free(pgs_aead_cryptor_t *ptr);
bool pgs_aead_cryptor_encrypt(pgs_aead_cryptor_t *ptr,
			      const pgs_buf_t *plaintext, int plaintext_len,
			      pgs_buf_t *tag, pgs_buf_t *ciphertext,
			      int *ciphertext_len);
bool pgs_aead_cryptor_decrypt(pgs_aead_cryptor_t *ptr,
			      const pgs_buf_t *ciphertext, int ciphertext_len,
			      const pgs_buf_t *tag, pgs_buf_t *plaintext,
			      int *plaintext_len);
void pgs_aead_cryptor_increase_iv(pgs_aead_cryptor_t *ptr);

#endif
