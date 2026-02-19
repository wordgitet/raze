#include "fuzz_common.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../../src/format/rar5/file_header.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	RazeRar5BlockHeader block;
	RazeRar5FileHeader fh;
	size_t body_offset;
	size_t extra_offset;
	RazeStatus status;

	if (data == 0 || size < 4U || size > RAZE_FUZZ_MAX_INPUT) {
		return 0;
	}

	memset(&block, 0, sizeof(block));
	body_offset = (size_t)data[0] % size;
	extra_offset = body_offset + ((size_t)data[1] % (size - body_offset));
	block.body_offset = body_offset;
	block.extra_offset = extra_offset;
	block.extra_size = (uint64_t)(size - extra_offset);
	block.data_size = (uint64_t)data[2] * 8U;
	block.flags = (uint64_t)data[3];

	status = raze_rar5_parse_file_header(
		&block,
		(const unsigned char *)data,
		size,
		&fh
	);
	if (status == RAZE_STATUS_OK) {
		raze_rar5_file_header_free(&fh);
	}

	return 0;
}
