#include "pgs_util.h"
#include "../3rd-party/sha3.h"
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

pgs_buf_t *to_hexstring(const pgs_buf_t *buf, pgs_size_t size)
{
	pgs_buf_t *hexbuf = pgs_malloc(sizeof(pgs_buf_t) * (2 * size + 1));
	for (int i = 0; i < size; i++) {
		sprintf((char *)hexbuf + i * 2, "%02x", (int)buf[i]);
	}
	hexbuf[2 * size] = '\0';
	return hexbuf;
}
