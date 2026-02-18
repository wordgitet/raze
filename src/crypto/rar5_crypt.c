#include "rar5_crypt.h"

#if defined(RAZE_HAVE_OPENSSL) && RAZE_HAVE_OPENSSL
#include <openssl/evp.h>
#endif

int raze_rar5_crypto_available(void)
{
#if defined(RAZE_HAVE_OPENSSL) && RAZE_HAVE_OPENSSL
	return 1;
#else
	return 0;
#endif
}

int raze_rar5_aes256_cbc_decrypt(
	const unsigned char key[RAZE_RAR5_KEY_SIZE],
	const unsigned char iv[RAZE_RAR5_INITV_SIZE],
	const unsigned char *in,
	size_t len,
	unsigned char *out
)
{
#if defined(RAZE_HAVE_OPENSSL) && RAZE_HAVE_OPENSSL
	EVP_CIPHER_CTX *ctx;
	int out_len1 = 0;
	int out_len2 = 0;

	if (key == 0 || iv == 0 || in == 0 || out == 0) {
		return 0;
	}
	if ((len & 15U) != 0U) {
		return 0;
	}

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == 0) {
		return 0;
	}

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), 0, key, iv) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}
	if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}
	if (EVP_DecryptUpdate(ctx, out, &out_len1, in, (int)len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}
	if (EVP_DecryptFinal_ex(ctx, out + out_len1, &out_len2) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}
	EVP_CIPHER_CTX_free(ctx);
	return ((size_t)(out_len1 + out_len2)) == len;
#else
	(void)key;
	(void)iv;
	(void)in;
	(void)len;
	(void)out;
	return 0;
#endif
}
