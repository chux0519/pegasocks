#include "pgs_util.h"
#include "../3rd-party/sha3.h"
#include "../3rd-party/fnv.h"
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <assert.h>

void sha224(const pgs_buf_t *input, pgs_size_t input_len, pgs_buf_t *res,
	    pgs_size_t *res_len)
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

void shake128(const pgs_buf_t *input, pgs_size_t input_len, pgs_buf_t *out,
	      pgs_size_t out_len)
{
	sha3_ctx_t sha3;
	shake128_init(&sha3);
	shake_update(&sha3, input, input_len);
	shake_xof(&sha3);
	shake_out(&sha3, out, out_len);
	return;
}

void hmac_md5(const pgs_buf_t *key, pgs_size_t key_len, const pgs_buf_t *data,
	      pgs_size_t data_len, pgs_buf_t *out, pgs_size_t *out_len)
{
	HMAC(EVP_md5(), key, key_len, data, data_len, out,
	     (unsigned int *)out_len);
	assert(*out_len == 16);
}

void md5(const pgs_buf_t *input, pgs_size_t input_len, pgs_buf_t *res)
{
	MD5(input, input_len, res);
}

int fnv1a(void *input, pgs_size_t input_len)
{
	return fnv_32a_buf(input, input_len, FNV1_32A_INIT);
}

pgs_buf_t *to_hexstring(const pgs_buf_t *buf, pgs_size_t size)
{
	pgs_buf_t *hexbuf = pgs_malloc(sizeof(pgs_buf_t) * (2 * size + 1));
	for (int i = 0; i < size; i++) {
		sprintf((char *)hexbuf + i * 2, "%02x", (int)buf[i]);
	}
	hexbuf[2 * size] = '\0';
	return hexbuf;
}

int aes_128_cfb(const pgs_buf_t *plaintext, int plaintext_len,
		const pgs_buf_t *key, const pgs_buf_t *iv,
		pgs_buf_t *ciphertext)
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
	perror("aes_128_cfb");
	return -1;
}
