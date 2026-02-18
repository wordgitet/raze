#include "extract_compressed.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "../checksum/crc32.h"
#include "rar5/unpack_v50.h"

void raze_compressed_scratch_init(RazeCompressedScratch *scratch)
{
	if (scratch == 0) {
		return;
	}

	scratch->packed = 0;
	scratch->packed_capacity = 0;
	scratch->unpacked = 0;
	scratch->unpacked_capacity = 0;
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

static RazeStatus write_exact_payload(
	FILE *output,
	const unsigned char *buf,
	size_t size,
	int crc32_present,
	uint32_t expected_crc32
)
{
	size_t offset = 0;
	uint32_t crc = raze_crc32_init();

	while (offset < size) {
		size_t nwritten = fwrite(buf + offset, 1, size - offset, output);
		if (nwritten == 0) {
			return RAZE_STATUS_IO;
		}
		if (crc32_present) {
			crc = raze_crc32_update(crc, buf + offset, nwritten);
		}
		offset += nwritten;
	}

	if (crc32_present && raze_crc32_final(crc) != expected_crc32) {
		return RAZE_STATUS_CRC_MISMATCH;
	}

	return RAZE_STATUS_OK;
}

static RazeStatus verify_empty_crc32(uint32_t expected_crc)
{
	uint32_t crc = raze_crc32_init();
	uint32_t actual = raze_crc32_final(crc);

	if (actual != expected_crc) {
		return RAZE_STATUS_CRC_MISMATCH;
	}

	return RAZE_STATUS_OK;
}

RazeStatus raze_extract_compressed_payload(
	FILE *archive,
	FILE *output,
	const RazeRar5FileHeader *fh,
	RazeCompressedScratch *scratch
)
{
	unsigned char *packed = 0;
	unsigned char *unpacked = 0;
	unsigned char *local_packed = 0;
	unsigned char *local_unpacked = 0;
	size_t packed_size;
	size_t packed_alloc_size;
	size_t unpacked_size;
	int extra_dist = 0;
	RazeStatus status = RAZE_STATUS_OK;

	if (archive == 0 || output == 0 || fh == 0) {
		return RAZE_STATUS_BAD_ARGUMENT;
	}
	if (fh->method == 0 || fh->method > 5) {
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
			return verify_empty_crc32(fh->crc32);
		}
		return RAZE_STATUS_OK;
	}
	if (packed_size == 0 || unpacked_size == 0) {
		return RAZE_STATUS_BAD_ARCHIVE;
	}

	if (scratch != 0) {
		if (!ensure_scratch_capacity(&scratch->packed, &scratch->packed_capacity, packed_alloc_size)) {
			return RAZE_STATUS_IO;
		}
		if (!ensure_scratch_capacity(&scratch->unpacked, &scratch->unpacked_capacity, unpacked_size)) {
			return RAZE_STATUS_IO;
		}
		packed = scratch->packed;
		unpacked = scratch->unpacked;
	} else {
		local_packed = (unsigned char *)malloc(packed_alloc_size);
		if (local_packed == 0) {
			return RAZE_STATUS_IO;
		}
		local_unpacked = (unsigned char *)malloc(unpacked_size);
		if (local_unpacked == 0) {
			free(local_packed);
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

	if (fh->comp_version == 1 && !fh->comp_is_v50_compat) {
		extra_dist = 1;
	}

	status = raze_rar5_unpack_v50(
		packed,
		packed_size,
		unpacked,
		unpacked_size,
		extra_dist
	);
	if (status != RAZE_STATUS_OK) {
		goto done;
	}

	status = write_exact_payload(
		output,
		unpacked,
		unpacked_size,
		fh->crc32_present,
		fh->crc32
	);

done:
	free(local_unpacked);
	free(local_packed);
	return status;
}
