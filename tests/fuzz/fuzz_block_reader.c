#define _GNU_SOURCE
#include "fuzz_common.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../src/format/rar5/block_reader.h"

static int fuzz_skip_forward(FILE *file, uint64_t bytes)
{
	while (bytes > 0U) {
		long chunk;

		if (bytes > (uint64_t)LONG_MAX) {
			chunk = LONG_MAX;
		} else {
			chunk = (long)bytes;
		}
		if (fseek(file, chunk, SEEK_CUR) != 0) {
			return 0;
		}
		bytes -= (uint64_t)chunk;
	}
	return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FILE *file;
	size_t loops = 0;

	if (data == 0 || size == 0 || size > RAZE_FUZZ_MAX_INPUT) {
		return 0;
	}

	file = fmemopen((void *)data, size, "rb");
	if (file == 0) {
		return 0;
	}

	if (raze_rar5_read_signature(file) == RAZE_STATUS_OK) {
		for (loops = 0; loops < 16U; ++loops) {
			RazeRar5BlockHeader block;
			unsigned char *buf = 0;
			size_t buf_len = 0;
			RazeStatus status = RAZE_STATUS_OK;
			RazeRar5ReadResult rr = raze_rar5_read_block(
				file,
				&block,
				&buf,
				&buf_len,
				&status
			);

			free(buf);
			if (rr != RAZE_RAR5_READ_OK) {
				break;
			}
			if (!fuzz_skip_forward(file, block.data_size)) {
				break;
			}
		}
	}

	fclose(file);
	return 0;
}
