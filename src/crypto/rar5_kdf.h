#ifndef RAZE_CRYPTO_RAR5_KDF_H
#define RAZE_CRYPTO_RAR5_KDF_H

#include <stddef.h>
#include <stdint.h>

#define RAZE_RAR5_SALT_SIZE 16U
#define RAZE_RAR5_INITV_SIZE 16U
#define RAZE_RAR5_PSWCHECK_SIZE 8U
#define RAZE_RAR5_PSWCHECK_CSUM_SIZE 4U
#define RAZE_RAR5_KEY_SIZE 32U
#define RAZE_RAR5_HASH_KEY_SIZE 32U
#define RAZE_RAR5_KDF_LG2_MAX 24U

int raze_rar5_kdf_derive(
	const char *password_utf8,
	const unsigned char salt[RAZE_RAR5_SALT_SIZE],
	uint8_t lg2_count,
	unsigned char key_out[RAZE_RAR5_KEY_SIZE],
	unsigned char hash_key_out[RAZE_RAR5_HASH_KEY_SIZE],
	unsigned char psw_value_out[RAZE_RAR5_KEY_SIZE]
);

int raze_rar5_pswcheck_from_value(
	const unsigned char psw_value[RAZE_RAR5_KEY_SIZE],
	unsigned char psw_check_out[RAZE_RAR5_PSWCHECK_SIZE],
	unsigned char psw_check_csum_out[RAZE_RAR5_PSWCHECK_CSUM_SIZE]
);

int raze_rar5_pswcheck_validate(
	const unsigned char psw_check[RAZE_RAR5_PSWCHECK_SIZE],
	const unsigned char psw_check_csum[RAZE_RAR5_PSWCHECK_CSUM_SIZE]
);

int raze_rar5_crc32_to_mac(
	uint32_t crc32_value,
	const unsigned char hash_key[RAZE_RAR5_HASH_KEY_SIZE],
	uint32_t *mac_out
);

#endif
