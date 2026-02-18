#include "rar5_kdf.h"

#include <string.h>

#if defined(RAZE_HAVE_OPENSSL) && RAZE_HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif

static void secure_zero(void *ptr, size_t len)
{
	volatile unsigned char *p = (volatile unsigned char *)ptr;
	while (len-- > 0U) {
		*p++ = 0U;
	}
}

#if defined(RAZE_HAVE_OPENSSL) && RAZE_HAVE_OPENSSL
static int hmac_sha256(
	const unsigned char *key,
	size_t key_len,
	const unsigned char *data,
	size_t data_len,
	unsigned char out[32]
)
{
	unsigned int out_len = 0U;

	if (HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &out_len) == 0) {
		return 0;
	}
	return out_len == 32U;
}
#endif

int raze_rar5_kdf_derive(
	const char *password_utf8,
	const unsigned char salt[RAZE_RAR5_SALT_SIZE],
	uint8_t lg2_count,
	unsigned char key_out[RAZE_RAR5_KEY_SIZE],
	unsigned char hash_key_out[RAZE_RAR5_HASH_KEY_SIZE],
	unsigned char psw_value_out[RAZE_RAR5_KEY_SIZE]
)
{
#if defined(RAZE_HAVE_OPENSSL) && RAZE_HAVE_OPENSSL
	unsigned char salt_plus_index[RAZE_RAR5_SALT_SIZE + 4U];
	unsigned char u[32];
	unsigned char f[32];
	size_t pwd_len;
	uint32_t count;
	uint32_t i;
	uint32_t j;

	if (password_utf8 == 0 || salt == 0 || key_out == 0 || hash_key_out == 0 || psw_value_out == 0) {
		return 0;
	}
	if (lg2_count > RAZE_RAR5_KDF_LG2_MAX) {
		return 0;
	}

	count = 1U << lg2_count;
	if (count == 0U) {
		return 0;
	}

	pwd_len = strlen(password_utf8);
	memcpy(salt_plus_index, salt, RAZE_RAR5_SALT_SIZE);
	salt_plus_index[RAZE_RAR5_SALT_SIZE + 0U] = 0U;
	salt_plus_index[RAZE_RAR5_SALT_SIZE + 1U] = 0U;
	salt_plus_index[RAZE_RAR5_SALT_SIZE + 2U] = 0U;
	salt_plus_index[RAZE_RAR5_SALT_SIZE + 3U] = 1U;

	if (!hmac_sha256(
			(const unsigned char *)password_utf8,
			pwd_len,
			salt_plus_index,
			sizeof(salt_plus_index),
			u
		)) {
		secure_zero(salt_plus_index, sizeof(salt_plus_index));
		return 0;
	}
	memcpy(f, u, sizeof(f));

	for (i = 0U; i < count - 1U; ++i) {
		if (!hmac_sha256((const unsigned char *)password_utf8, pwd_len, u, sizeof(u), u)) {
			secure_zero(salt_plus_index, sizeof(salt_plus_index));
			secure_zero(u, sizeof(u));
			secure_zero(f, sizeof(f));
			return 0;
		}
		for (j = 0U; j < sizeof(f); ++j) {
			f[j] ^= u[j];
		}
	}
	memcpy(key_out, f, RAZE_RAR5_KEY_SIZE);

	for (i = 0U; i < 16U; ++i) {
		if (!hmac_sha256((const unsigned char *)password_utf8, pwd_len, u, sizeof(u), u)) {
			secure_zero(salt_plus_index, sizeof(salt_plus_index));
			secure_zero(u, sizeof(u));
			secure_zero(f, sizeof(f));
			return 0;
		}
		for (j = 0U; j < sizeof(f); ++j) {
			f[j] ^= u[j];
		}
	}
	memcpy(hash_key_out, f, RAZE_RAR5_HASH_KEY_SIZE);

	for (i = 0U; i < 16U; ++i) {
		if (!hmac_sha256((const unsigned char *)password_utf8, pwd_len, u, sizeof(u), u)) {
			secure_zero(salt_plus_index, sizeof(salt_plus_index));
			secure_zero(u, sizeof(u));
			secure_zero(f, sizeof(f));
			return 0;
		}
		for (j = 0U; j < sizeof(f); ++j) {
			f[j] ^= u[j];
		}
	}
	memcpy(psw_value_out, f, RAZE_RAR5_KEY_SIZE);

	secure_zero(salt_plus_index, sizeof(salt_plus_index));
	secure_zero(u, sizeof(u));
	secure_zero(f, sizeof(f));
	return 1;
#else
	(void)password_utf8;
	(void)salt;
	(void)lg2_count;
	(void)key_out;
	(void)hash_key_out;
	(void)psw_value_out;
	return 0;
#endif
}

int raze_rar5_pswcheck_from_value(
	const unsigned char psw_value[RAZE_RAR5_KEY_SIZE],
	unsigned char psw_check_out[RAZE_RAR5_PSWCHECK_SIZE],
	unsigned char psw_check_csum_out[RAZE_RAR5_PSWCHECK_CSUM_SIZE]
)
{
#if defined(RAZE_HAVE_OPENSSL) && RAZE_HAVE_OPENSSL
	unsigned char digest[32];
	size_t i;

	if (psw_value == 0 || psw_check_out == 0 || psw_check_csum_out == 0) {
		return 0;
	}

	memset(psw_check_out, 0, RAZE_RAR5_PSWCHECK_SIZE);
	for (i = 0U; i < RAZE_RAR5_KEY_SIZE; ++i) {
		psw_check_out[i % RAZE_RAR5_PSWCHECK_SIZE] ^= psw_value[i];
	}

	if (EVP_Digest(psw_check_out, RAZE_RAR5_PSWCHECK_SIZE, digest, 0, EVP_sha256(), 0) != 1) {
		secure_zero(digest, sizeof(digest));
		return 0;
	}
	memcpy(psw_check_csum_out, digest, RAZE_RAR5_PSWCHECK_CSUM_SIZE);
	secure_zero(digest, sizeof(digest));
	return 1;
#else
	(void)psw_value;
	(void)psw_check_out;
	(void)psw_check_csum_out;
	return 0;
#endif
}

int raze_rar5_pswcheck_validate(
	const unsigned char psw_check[RAZE_RAR5_PSWCHECK_SIZE],
	const unsigned char psw_check_csum[RAZE_RAR5_PSWCHECK_CSUM_SIZE]
)
{
#if defined(RAZE_HAVE_OPENSSL) && RAZE_HAVE_OPENSSL
	unsigned char digest[32];

	if (psw_check == 0 || psw_check_csum == 0) {
		return 0;
	}

	if (EVP_Digest(psw_check, RAZE_RAR5_PSWCHECK_SIZE, digest, 0, EVP_sha256(), 0) != 1) {
		secure_zero(digest, sizeof(digest));
		return 0;
	}
	if (memcmp(psw_check_csum, digest, RAZE_RAR5_PSWCHECK_CSUM_SIZE) != 0) {
		secure_zero(digest, sizeof(digest));
		return 0;
	}
	secure_zero(digest, sizeof(digest));
	return 1;
#else
	(void)psw_check;
	(void)psw_check_csum;
	return 0;
#endif
}

int raze_rar5_crc32_to_mac(
	uint32_t crc32_value,
	const unsigned char hash_key[RAZE_RAR5_HASH_KEY_SIZE],
	uint32_t *mac_out
)
{
#if defined(RAZE_HAVE_OPENSSL) && RAZE_HAVE_OPENSSL
	unsigned char crc_raw[4];
	unsigned char digest[32];
	uint32_t out = 0U;
	size_t i;

	if (hash_key == 0 || mac_out == 0) {
		return 0;
	}

	crc_raw[0] = (unsigned char)(crc32_value & 0xffU);
	crc_raw[1] = (unsigned char)((crc32_value >> 8U) & 0xffU);
	crc_raw[2] = (unsigned char)((crc32_value >> 16U) & 0xffU);
	crc_raw[3] = (unsigned char)((crc32_value >> 24U) & 0xffU);

	if (!hmac_sha256(hash_key, RAZE_RAR5_HASH_KEY_SIZE, crc_raw, sizeof(crc_raw), digest)) {
		return 0;
	}

	for (i = 0U; i < sizeof(digest); ++i) {
		out ^= (uint32_t)digest[i] << ((i & 3U) * 8U);
	}

	*mac_out = out;
	secure_zero(digest, sizeof(digest));
	return 1;
#else
	(void)crc32_value;
	(void)hash_key;
	(void)mac_out;
	return 0;
#endif
}
