#include "extract_compressed.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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

void raze_compressed_scratch_init(RazeCompressedScratch *scratch)
{
	if (scratch == 0) {
		return;
	}

	scratch->packed = 0;
	scratch->packed_capacity = 0;
	scratch->decrypted_packed = 0;
	scratch->decrypted_packed_capacity = 0;
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
	free(scratch->decrypted_packed);
	free(scratch->unpacked);
	scratch->packed = 0;
	scratch->packed_capacity = 0;
	scratch->decrypted_packed = 0;
	scratch->decrypted_packed_capacity = 0;
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
	int use_hash_key,
	const unsigned char *hash_key
)
{
	size_t offset = 0;
	uint32_t crc = raze_crc32_init();

	while (offset < size) {
		size_t chunk = size - offset;
		size_t nwritten = chunk;

		if (output != 0) {
			nwritten = fwrite(buf + offset, 1, chunk, output);
			if (nwritten == 0) {
				return RAZE_STATUS_IO;
			}
		}
		if (crc32_present) {
			crc = raze_crc32_update(crc, buf + offset, nwritten);
		}
		offset += nwritten;
	}

	if (crc32_present) {
		uint32_t actual = raze_crc32_final(crc);
		if (use_hash_key) {
			if (!raze_rar5_crc32_to_mac(actual, hash_key, &actual)) {
				return RAZE_STATUS_UNSUPPORTED_FEATURE;
			}
		}
		if (actual != expected_crc32) {
			return RAZE_STATUS_CRC_MISMATCH;
		}
	}

	return RAZE_STATUS_OK;
}

static RazeStatus verify_empty_crc32(
	uint32_t expected_crc,
	int use_hash_key,
	const unsigned char *hash_key
)
{
	uint32_t crc = raze_crc32_init();
	uint32_t actual = raze_crc32_final(crc);

	if (use_hash_key) {
		if (!raze_rar5_crc32_to_mac(actual, hash_key, &actual)) {
			return RAZE_STATUS_UNSUPPORTED_FEATURE;
		}
	}
	if (actual != expected_crc) {
		return RAZE_STATUS_CRC_MISMATCH;
	}

	return RAZE_STATUS_OK;
}

static RazeStatus decrypt_packed_payload_if_needed(
	const RazeRar5FileHeader *fh,
	const char *password,
	int password_present,
	const unsigned char *packed_in,
	size_t packed_size,
	unsigned char *packed_out,
	unsigned char out_key[RAZE_RAR5_KEY_SIZE],
	unsigned char out_hash_key[RAZE_RAR5_HASH_KEY_SIZE]
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
		memcpy(packed_out, packed_in, packed_size);
		return RAZE_STATUS_OK;
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
	if (!raze_rar5_kdf_derive(
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

	if (!raze_rar5_aes256_cbc_decrypt(out_key, fh->crypt_initv, packed_in, packed_size, packed_out)) {
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
	unsigned char *decrypted_packed = 0;
	unsigned char *unpacked = 0;
	unsigned char *local_packed = 0;
	unsigned char *local_decrypted_packed = 0;
	unsigned char *local_unpacked = 0;
	unsigned char zero_output = 0;
	size_t packed_size;
	size_t packed_alloc_size;
	size_t unpacked_size;
	size_t decrypted_size;
	int extra_dist = 0;
	int use_hash_key = 0;
	unsigned char key[RAZE_RAR5_KEY_SIZE];
	unsigned char hash_key[RAZE_RAR5_HASH_KEY_SIZE];
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
	unpacked_size = (size_t)fh->unp_size;
	if (packed_size > SIZE_MAX - 8U) {
		return RAZE_STATUS_UNSUPPORTED_FEATURE;
	}
	packed_alloc_size = packed_size + 8U;

	if (packed_size == 0 && unpacked_size == 0) {
		if (fh->crc32_present) {
			return verify_empty_crc32(fh->crc32, 0, 0);
		}
		return RAZE_STATUS_OK;
	}
	if (packed_size == 0) {
		return RAZE_STATUS_BAD_ARCHIVE;
	}

	if (scratch != 0) {
		if (!ensure_scratch_capacity(&scratch->packed, &scratch->packed_capacity, packed_alloc_size)) {
			return RAZE_STATUS_IO;
		}
		if (!ensure_scratch_capacity(
				&scratch->decrypted_packed,
				&scratch->decrypted_packed_capacity,
				packed_alloc_size
			)) {
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
		decrypted_packed = scratch->decrypted_packed;
		unpacked = scratch->unpacked;
	} else {
		local_packed = (unsigned char *)malloc(packed_alloc_size);
		local_decrypted_packed = (unsigned char *)malloc(packed_alloc_size);
		local_unpacked = (unsigned char *)malloc(unpacked_size > 0U ? unpacked_size : 1U);
		if (local_packed == 0 || local_decrypted_packed == 0 || local_unpacked == 0) {
			free(local_packed);
			free(local_decrypted_packed);
			free(local_unpacked);
			return RAZE_STATUS_IO;
		}
		packed = local_packed;
		decrypted_packed = local_decrypted_packed;
		unpacked = local_unpacked;
	}

	status = read_exact_payload(archive, packed, packed_size);
	if (status != RAZE_STATUS_OK) {
		goto done;
	}
	memset(packed + packed_size, 0, 8U);

	status = decrypt_packed_payload_if_needed(
		fh,
		password,
		password_present,
		packed,
		packed_size,
		decrypted_packed,
		key,
		hash_key
	);
	if (status != RAZE_STATUS_OK) {
		goto done;
	}
	decrypted_size = packed_size;
	use_hash_key = fh->encrypted && fh->crypt_use_hash_key;

	if (fh->method == 0U) {
		if (decrypted_size < unpacked_size) {
			status = RAZE_STATUS_BAD_ARCHIVE;
			goto done;
		}
		status = write_or_verify_payload(
			output,
			unpacked_size > 0U ? decrypted_packed : &zero_output,
			unpacked_size,
			fh->crc32_present,
			fh->crc32,
			use_hash_key,
			hash_key
		);
		goto done;
	}

	if (fh->comp_version == 1 && !fh->comp_is_v50_compat) {
		extra_dist = 1;
	}

	if (scratch != 0) {
		status = raze_rar5_unpack_ctx_decode_file(
			&scratch->unpack_ctx,
			decrypted_packed,
			decrypted_size,
			unpacked_size > 0U ? unpacked : &zero_output,
			unpacked_size,
			(size_t)fh->dict_size_bytes,
			extra_dist,
			solid_stream
		);
	} else {
		raze_rar5_unpack_ctx_init(&local_ctx);
		status = raze_rar5_unpack_ctx_decode_file(
			&local_ctx,
			decrypted_packed,
			decrypted_size,
			unpacked_size > 0U ? unpacked : &zero_output,
			unpacked_size,
			(size_t)fh->dict_size_bytes,
			extra_dist,
			solid_stream
		);
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
		use_hash_key,
		hash_key
	);

done:
	secure_zero(key, sizeof(key));
	secure_zero(hash_key, sizeof(hash_key));
	free(local_unpacked);
	free(local_decrypted_packed);
	free(local_packed);
	return status;
}
