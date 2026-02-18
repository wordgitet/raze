#include "extract_compressed.h"

#include <limits.h>
#include <stdlib.h>

#include "../checksum/crc32.h"
#include "rar5/unpack_v50.h"

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

static RazeStatus write_exact_payload(FILE *output, const unsigned char *buf, size_t size)
{
	size_t offset = 0;

	while (offset < size) {
		size_t nwritten = fwrite(buf + offset, 1, size - offset, output);
		if (nwritten == 0) {
			return RAZE_STATUS_IO;
		}
		offset += nwritten;
	}

	return RAZE_STATUS_OK;
}

static RazeStatus verify_crc32(
	const RazeRar5FileHeader *fh,
	const unsigned char *data,
	size_t data_size
)
{
	uint32_t crc;
	uint32_t actual;

	if (fh == 0 || data == 0) {
		return RAZE_STATUS_BAD_ARGUMENT;
	}
	if (!fh->crc32_present) {
		return RAZE_STATUS_OK;
	}

	crc = raze_crc32_init();
	crc = raze_crc32_update(crc, data, data_size);
	actual = raze_crc32_final(crc);

	if (actual != fh->crc32) {
		return RAZE_STATUS_CRC_MISMATCH;
	}
	return RAZE_STATUS_OK;
}

RazeStatus raze_extract_compressed_payload(
	FILE *archive,
	FILE *output,
	const RazeRar5FileHeader *fh
)
{
	unsigned char *packed = 0;
	unsigned char *unpacked = 0;
	size_t packed_size;
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

	if (packed_size == 0 && unpacked_size == 0) {
		return verify_crc32(fh, (const unsigned char *)"", 0);
	}
	if (packed_size == 0 || unpacked_size == 0) {
		return RAZE_STATUS_BAD_ARCHIVE;
	}

	packed = (unsigned char *)malloc(packed_size);
	if (packed == 0) {
		return RAZE_STATUS_IO;
	}

	unpacked = (unsigned char *)malloc(unpacked_size);
	if (unpacked == 0) {
		free(packed);
		return RAZE_STATUS_IO;
	}

	status = read_exact_payload(archive, packed, packed_size);
	if (status != RAZE_STATUS_OK) {
		goto done;
	}

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

	status = verify_crc32(fh, unpacked, unpacked_size);
	if (status != RAZE_STATUS_OK) {
		goto done;
	}

	status = write_exact_payload(output, unpacked, unpacked_size);

done:
	free(unpacked);
	free(packed);
	return status;
}
