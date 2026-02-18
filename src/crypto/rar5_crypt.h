#ifndef RAZE_CRYPTO_RAR5_CRYPT_H
#define RAZE_CRYPTO_RAR5_CRYPT_H

#include <stddef.h>
#include <stdint.h>

#include "rar5_kdf.h"

int raze_rar5_crypto_available(void);

int raze_rar5_aes256_cbc_decrypt(
	const unsigned char key[RAZE_RAR5_KEY_SIZE],
	const unsigned char iv[RAZE_RAR5_INITV_SIZE],
	const unsigned char *in,
	size_t len,
	unsigned char *out
);

#endif
