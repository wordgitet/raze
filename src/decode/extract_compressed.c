#include "extract_compressed.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../checksum/blake2sp.h"
#include "../checksum/crc32.h"
#include "../crypto/rar5_crypt.h"
#include "../crypto/rar5_kdf.h"

static void secure_zero(void *ptr, size_t len)
{
	volatile unsigned char *p = (volatile unsigned char *)ptr;
	while (len-- > 0U) {
		*p++ = 0U;
	}
}

static int enc_profile_enabled(void)
{
	static int initialized = 0;
	static int enabled = 0;
	const char *value;

	if (initialized) {
		return enabled;
	}

	value = getenv("RAZE_PROFILE_ENC");
	if (value != 0 && value[0] == '1' && value[1] == '\0') {
		enabled = 1;
	}
	initialized = 1;
	return enabled;
}

static uint64_t monotonic_ns(void)
{
	struct timespec ts;

#if defined(CLOCK_MONOTONIC)
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		return 0U;
	}
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#else
	if (timespec_get(&ts, TIME_UTC) != TIME_UTC) {
		return 0U;
	}
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

static void profile_add_elapsed(uint64_t *slot, uint64_t t0)
{
	uint64_t t1;

	if (slot == 0 || t0 == 0U) {
		return;
	}
	t1 = monotonic_ns();
	if (t1 > t0) {
		*slot += t1 - t0;
	}
}

static double ns_to_ms(uint64_t ns)
{
	return (double)ns / 1000000.0;
}

void raze_compressed_scratch_init(RazeCompressedScratch *scratch)
{
	if (scratch == 0) {
		return;
	}

	scratch->packed = 0;
	scratch->packed_capacity = 0;
	scratch->unpacked = 0;
	scratch->unpacked_capacity = 0;
	raze_rar5_unpack_ctx_init(&scratch->unpack_ctx);
}

void raze_compressed_scratch_free(RazeCompressedScratch *scratch)
{
	if (scratch == 0) {
		return;
	}

	free(scratch->packed);
	free(scratch->unpacked);
	scratch->packed = 0;
	scratch->packed_capacity = 0;
	scratch->unpacked = 0;
	scratch->unpacked_capacity = 0;
	raze_rar5_unpack_ctx_free(&scratch->unpack_ctx);
}

void raze_compressed_scratch_reset_solid_stream(RazeCompressedScratch *scratch)
{
	if (scratch == 0) {
		return;
	}
	raze_rar5_unpack_ctx_reset_for_new_stream(&scratch->unpack_ctx);
}

static int ensure_scratch_capacity(unsigned char **buf, size_t *capacity, size_t need)
{
	unsigned char *expanded;

	if (buf == 0 || capacity == 0) {
		return 0;
	}
	if (*capacity >= need) {
		return 1;
	}

	expanded = (unsigned char *)realloc(*buf, need);
	if (expanded == 0) {
		return 0;
	}
	*buf = expanded;
	*capacity = need;
	return 1;
}

static RazeStatus read_exact_payload(FILE *archive, unsigned char *buf, size_t size)
{
	size_t offset = 0;

	while (offset < size) {
		size_t nread = fread(buf + offset, 1, size - offset, archive);
		if (nread == 0) {
			if (feof(archive)) {
				return RAZE_STATUS_BAD_ARCHIVE;
			}
			return RAZE_STATUS_IO;
		}
		offset += nread;
	}

	return RAZE_STATUS_OK;
}

static RazeStatus write_or_verify_payload(
	FILE *output,
	const unsigned char *buf,
	size_t size,
	int crc32_present,
	uint32_t expected_crc32,
	int hash_present,
	uint8_t hash_type,
	const unsigned char expected_hash[RAZE_BLAKE2SP_DIGEST_SIZE],
	int use_hash_key,
	const unsigned char *hash_key,
	uint64_t *write_ns,
	uint64_t *hash_verify_ns
)
{
	size_t offset = 0;
	uint32_t crc = raze_crc32_init();
	RazeBlake2spState blake_state;
	unsigned char actual_hash[RAZE_BLAKE2SP_DIGEST_SIZE];
	unsigned char mac_hash[RAZE_BLAKE2SP_DIGEST_SIZE];
	const unsigned char *compare_hash = actual_hash;

	memset(actual_hash, 0, sizeof(actual_hash));
	memset(mac_hash, 0, sizeof(mac_hash));
	if (hash_present) {
		if (hash_type != RAZE_RAR5_HASH_TYPE_BLAKE2SP) {
			return RAZE_STATUS_UNSUPPORTED_FEATURE;
		}
		raze_blake2sp_init(&blake_state);
	}

	while (offset < size) {
		size_t chunk = size - offset;
		size_t nwritten = chunk;

		if (output != 0) {
			uint64_t t0 = 0U;

			if (write_ns != 0) {
				t0 = monotonic_ns();
			}
			nwritten = fwrite(buf + offset, 1, chunk, output);
			if (nwritten == 0) {
				return RAZE_STATUS_IO;
			}
			if (write_ns != 0) {
				uint64_t t1 = monotonic_ns();
				if (t1 > t0) {
					*write_ns += t1 - t0;
				}
			}
		}
		if (crc32_present) {
			uint64_t t0 = 0U;

			if (hash_verify_ns != 0) {
				t0 = monotonic_ns();
			}
			crc = raze_crc32_update(crc, buf + offset, nwritten);
			if (hash_verify_ns != 0) {
				uint64_t t1 = monotonic_ns();
				if (t1 > t0) {
					*hash_verify_ns += t1 - t0;
				}
			}
		}
		if (hash_present) {
			uint64_t t0 = 0U;

			if (hash_verify_ns != 0) {
				t0 = monotonic_ns();
			}
			raze_blake2sp_update(&blake_state, buf + offset, nwritten);
			if (hash_verify_ns != 0) {
				uint64_t t1 = monotonic_ns();
				if (t1 > t0) {
					*hash_verify_ns += t1 - t0;
				}
			}
		}
		offset += nwritten;
	}

	if (crc32_present) {
		uint64_t t0 = 0U;
		uint32_t actual = raze_crc32_final(crc);

		if (hash_verify_ns != 0) {
			t0 = monotonic_ns();
		}
		if (use_hash_key) {
			if (!raze_rar5_crc32_to_mac(actual, hash_key, &actual)) {
				return RAZE_STATUS_UNSUPPORTED_FEATURE;
			}
		}
		if (actual != expected_crc32) {
			return RAZE_STATUS_CRC_MISMATCH;
		}
		if (hash_verify_ns != 0) {
			uint64_t t1 = monotonic_ns();
			if (t1 > t0) {
				*hash_verify_ns += t1 - t0;
			}
		}
	}
	if (hash_present) {
		uint64_t t0 = 0U;

		if (hash_verify_ns != 0) {
			t0 = monotonic_ns();
		}
		raze_blake2sp_final(&blake_state, actual_hash);
		if (use_hash_key) {
			if (!raze_rar5_digest_to_mac(actual_hash, hash_key, mac_hash)) {
				return RAZE_STATUS_UNSUPPORTED_FEATURE;
			}
			compare_hash = mac_hash;
		}
		if (memcmp(compare_hash, expected_hash, RAZE_BLAKE2SP_DIGEST_SIZE) != 0) {
			return RAZE_STATUS_CRC_MISMATCH;
		}
		if (hash_verify_ns != 0) {
			uint64_t t1 = monotonic_ns();
			if (t1 > t0) {
				*hash_verify_ns += t1 - t0;
			}
		}
	}

	return RAZE_STATUS_OK;
}

static RazeStatus verify_empty_integrity(
	const RazeRar5FileHeader *fh,
	int use_hash_key,
	const unsigned char *hash_key,
	uint64_t *write_ns,
	uint64_t *hash_verify_ns
)
{
	unsigned char zero = 0;

	if (fh == 0) {
		return RAZE_STATUS_BAD_ARGUMENT;
	}
	return write_or_verify_payload(
		0,
		&zero,
		0,
		fh->crc32_present,
		fh->crc32,
		fh->hash_present,
		fh->hash_type,
		fh->hash_value,
		use_hash_key,
		hash_key,
		write_ns,
		hash_verify_ns
	);
}

static RazeStatus decrypt_packed_payload_if_needed(
	const RazeRar5FileHeader *fh,
	const char *password,
	int password_present,
	const unsigned char *packed_in,
	size_t packed_size,
	unsigned char *packed_out,
	unsigned char out_key[RAZE_RAR5_KEY_SIZE],
	unsigned char out_hash_key[RAZE_RAR5_HASH_KEY_SIZE],
	uint64_t *kdf_ns,
	uint64_t *decrypt_ns
)
{
	unsigned char psw_value[RAZE_RAR5_KEY_SIZE];
	unsigned char psw_check[RAZE_RAR5_PSWCHECK_SIZE];
	unsigned char psw_check_csum[RAZE_RAR5_PSWCHECK_CSUM_SIZE];

	if (fh == 0 || packed_in == 0 || packed_out == 0 || out_key == 0 || out_hash_key == 0) {
		return RAZE_STATUS_BAD_ARGUMENT;
	}

	memset(out_key, 0, RAZE_RAR5_KEY_SIZE);
	memset(out_hash_key, 0, RAZE_RAR5_HASH_KEY_SIZE);

	if (!fh->encrypted) {
		return RAZE_STATUS_BAD_ARGUMENT;
	}
	if (!password_present || password == 0) {
		return RAZE_STATUS_BAD_ARGUMENT;
	}
	if (fh->crypt_version != 0U || !raze_rar5_crypto_available()) {
		return RAZE_STATUS_UNSUPPORTED_FEATURE;
	}
	if ((packed_size & 15U) != 0U) {
		return RAZE_STATUS_BAD_ARCHIVE;
	}
	if (kdf_ns != 0) {
		uint64_t t0 = monotonic_ns();
		if (!raze_rar5_kdf_derive(
				password,
				fh->crypt_salt,
				fh->crypt_lg2_count,
				out_key,
				out_hash_key,
				psw_value
			)) {
			profile_add_elapsed(kdf_ns, t0);
			return RAZE_STATUS_UNSUPPORTED_FEATURE;
		}
		profile_add_elapsed(kdf_ns, t0);
	} else if (!raze_rar5_kdf_derive(
			password,
			fh->crypt_salt,
			fh->crypt_lg2_count,
			out_key,
			out_hash_key,
			psw_value
		)) {
		return RAZE_STATUS_UNSUPPORTED_FEATURE;
	}
	if (fh->crypt_use_psw_check &&
	    raze_rar5_pswcheck_validate(fh->crypt_psw_check, fh->crypt_psw_check_csum)) {
		if (!raze_rar5_pswcheck_from_value(psw_value, psw_check, psw_check_csum)) {
			secure_zero(psw_value, sizeof(psw_value));
			return RAZE_STATUS_UNSUPPORTED_FEATURE;
		}
		if (memcmp(psw_check, fh->crypt_psw_check, RAZE_RAR5_PSWCHECK_SIZE) != 0) {
			secure_zero(psw_value, sizeof(psw_value));
			secure_zero(psw_check, sizeof(psw_check));
			secure_zero(psw_check_csum, sizeof(psw_check_csum));
			return RAZE_STATUS_CRC_MISMATCH;
		}
	}

	if (decrypt_ns != 0) {
		uint64_t t0 = monotonic_ns();
		if (!raze_rar5_aes256_cbc_decrypt(out_key, fh->crypt_initv, packed_in, packed_size, packed_out)) {
			profile_add_elapsed(decrypt_ns, t0);
			secure_zero(psw_value, sizeof(psw_value));
			secure_zero(psw_check, sizeof(psw_check));
			secure_zero(psw_check_csum, sizeof(psw_check_csum));
			return RAZE_STATUS_CRC_MISMATCH;
		}
		profile_add_elapsed(decrypt_ns, t0);
	} else if (!raze_rar5_aes256_cbc_decrypt(out_key, fh->crypt_initv, packed_in, packed_size, packed_out)) {
		secure_zero(psw_value, sizeof(psw_value));
		secure_zero(psw_check, sizeof(psw_check));
		secure_zero(psw_check_csum, sizeof(psw_check_csum));
		return RAZE_STATUS_CRC_MISMATCH;
	}

	secure_zero(psw_value, sizeof(psw_value));
	secure_zero(psw_check, sizeof(psw_check));
	secure_zero(psw_check_csum, sizeof(psw_check_csum));
	return RAZE_STATUS_OK;
}

RazeStatus raze_extract_compressed_payload(
	FILE *archive,
	FILE *output,
	const RazeRar5FileHeader *fh,
	RazeCompressedScratch *scratch,
	int solid_stream,
	const char *password,
	int password_present
)
{
	unsigned char *packed = 0;
	unsigned char *unpacked = 0;
	unsigned char *local_packed = 0;
	unsigned char *local_unpacked = 0;
	const unsigned char *packed_for_decode = 0;
	unsigned char zero_output = 0;
	size_t packed_size;
	size_t packed_alloc_size;
	size_t unpacked_size;
	size_t decrypted_size;
	int extra_dist = 0;
	int use_hash_key = 0;
	int profile_enabled = 0;
	unsigned char key[RAZE_RAR5_KEY_SIZE];
	unsigned char hash_key[RAZE_RAR5_HASH_KEY_SIZE];
	uint64_t kdf_ns = 0U;
	uint64_t decrypt_ns = 0U;
	uint64_t unpack_ns = 0U;
	uint64_t hash_verify_ns = 0U;
	uint64_t write_ns = 0U;
	RazeStatus status = RAZE_STATUS_OK;
	RazeRar5UnpackCtx local_ctx;

	if (archive == 0 || fh == 0) {
		return RAZE_STATUS_BAD_ARGUMENT;
	}
	if (fh->method > 5) {
		return RAZE_STATUS_UNSUPPORTED_FEATURE;
	}
	if (fh->comp_version > 1) {
		return RAZE_STATUS_UNSUPPORTED_FEATURE;
	}
	if (fh->pack_size > (uint64_t)SIZE_MAX || fh->unp_size > (uint64_t)SIZE_MAX) {
		return RAZE_STATUS_UNSUPPORTED_FEATURE;
	}

	packed_size = (size_t)fh->pack_size;
	profile_enabled = enc_profile_enabled() && fh->encrypted;
	unpacked_size = (size_t)fh->unp_size;
	if (packed_size > SIZE_MAX - 8U) {
		return RAZE_STATUS_UNSUPPORTED_FEATURE;
	}
	packed_alloc_size = packed_size + 8U;

	if (packed_size == 0 && unpacked_size == 0) {
		return verify_empty_integrity(
			fh,
			0,
			0,
			profile_enabled ? &write_ns : 0,
			profile_enabled ? &hash_verify_ns : 0
		);
	}
	if (packed_size == 0) {
		return RAZE_STATUS_BAD_ARCHIVE;
	}

	if (scratch != 0) {
		if (!ensure_scratch_capacity(&scratch->packed, &scratch->packed_capacity, packed_alloc_size)) {
			return RAZE_STATUS_IO;
		}
		if (!ensure_scratch_capacity(
				&scratch->unpacked,
				&scratch->unpacked_capacity,
				unpacked_size > 0U ? unpacked_size : 1U
			)) {
			return RAZE_STATUS_IO;
		}
		packed = scratch->packed;
		unpacked = scratch->unpacked;
	} else {
		local_packed = (unsigned char *)malloc(packed_alloc_size);
		local_unpacked = (unsigned char *)malloc(unpacked_size > 0U ? unpacked_size : 1U);
		if (local_packed == 0 || local_unpacked == 0) {
			free(local_packed);
			free(local_unpacked);
			return RAZE_STATUS_IO;
		}
		packed = local_packed;
		unpacked = local_unpacked;
	}

	status = read_exact_payload(archive, packed, packed_size);
	if (status != RAZE_STATUS_OK) {
		goto done;
	}
	memset(packed + packed_size, 0, 8U);

	if (fh->encrypted) {
		status = decrypt_packed_payload_if_needed(
			fh,
			password,
			password_present,
			packed,
			packed_size,
			packed,
			key,
			hash_key,
			profile_enabled ? &kdf_ns : 0,
			profile_enabled ? &decrypt_ns : 0
		);
		if (status != RAZE_STATUS_OK) {
			goto done;
		}
		packed_for_decode = packed;
		use_hash_key = fh->crypt_use_hash_key;
	} else {
		packed_for_decode = packed;
		use_hash_key = 0;
	}
	decrypted_size = packed_size;

	if (fh->method == 0U) {
		if (decrypted_size < unpacked_size) {
			status = RAZE_STATUS_BAD_ARCHIVE;
			goto done;
		}
		status = write_or_verify_payload(
			output,
			unpacked_size > 0U ? packed_for_decode : &zero_output,
			unpacked_size,
			fh->crc32_present,
			fh->crc32,
			fh->hash_present,
			fh->hash_type,
			fh->hash_value,
			use_hash_key,
			hash_key,
			profile_enabled ? &write_ns : 0,
			profile_enabled ? &hash_verify_ns : 0
		);
		goto done;
	}

	if (fh->comp_version == 1 && !fh->comp_is_v50_compat) {
		extra_dist = 1;
	}

	if (scratch != 0) {
		uint64_t t0 = 0U;
		if (profile_enabled) {
			t0 = monotonic_ns();
		}
		status = raze_rar5_unpack_ctx_decode_file(
			&scratch->unpack_ctx,
			packed_for_decode,
			decrypted_size,
			unpacked_size > 0U ? unpacked : &zero_output,
			unpacked_size,
			(size_t)fh->dict_size_bytes,
			extra_dist,
			solid_stream
		);
		profile_add_elapsed(profile_enabled ? &unpack_ns : 0, t0);
	} else {
		raze_rar5_unpack_ctx_init(&local_ctx);
		{
			uint64_t t0 = 0U;

			if (profile_enabled) {
				t0 = monotonic_ns();
			}
			status = raze_rar5_unpack_ctx_decode_file(
				&local_ctx,
				packed_for_decode,
				decrypted_size,
				unpacked_size > 0U ? unpacked : &zero_output,
				unpacked_size,
				(size_t)fh->dict_size_bytes,
				extra_dist,
				solid_stream
			);
			profile_add_elapsed(profile_enabled ? &unpack_ns : 0, t0);
		}
		raze_rar5_unpack_ctx_free(&local_ctx);
	}
	if (status != RAZE_STATUS_OK) {
		goto done;
	}

	status = write_or_verify_payload(
		output,
		unpacked_size > 0U ? unpacked : &zero_output,
		unpacked_size,
		fh->crc32_present,
		fh->crc32,
		fh->hash_present,
		fh->hash_type,
		fh->hash_value,
		use_hash_key,
		hash_key,
		profile_enabled ? &write_ns : 0,
		profile_enabled ? &hash_verify_ns : 0
	);

done:
	if (profile_enabled) {
		printf("[raze-enc-prof] entry='%s' kdf=%.3fms decrypt=%.3fms "
		       "unpack=%.3fms hash_verify=%.3fms write=%.3fms\n",
		       fh->name != 0 ? fh->name : "<unknown>",
		       ns_to_ms(kdf_ns),
		       ns_to_ms(decrypt_ns),
		       ns_to_ms(unpack_ns),
		       ns_to_ms(hash_verify_ns),
		       ns_to_ms(write_ns));
	}
	secure_zero(key, sizeof(key));
	secure_zero(hash_key, sizeof(hash_key));
	free(local_unpacked);
	free(local_packed);
	return status;
}
