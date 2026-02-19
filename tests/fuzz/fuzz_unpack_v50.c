#include "fuzz_common.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../src/decode/rar5/unpack_v50.h"

static size_t pick_dict_size(uint8_t selector)
{
	static const size_t dict_sizes[] = {
		128U * 1024U,
		256U * 1024U,
		512U * 1024U,
		1024U * 1024U,
		2U * 1024U * 1024U,
		4U * 1024U * 1024U
	};

	return dict_sizes[selector % (sizeof(dict_sizes) / sizeof(dict_sizes[0]))];
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	RazeRar5UnpackCtx ctx;
	unsigned char *output;
	size_t output_size;
	size_t packed_size;
	size_t dict_size;
	int extra_dist;
	int solid;

	if (data == 0 || size == 0 || size > RAZE_FUZZ_MAX_INPUT) {
		return 0;
	}

	output_size = (size_t)data[0] * 257U;
	if (output_size > RAZE_FUZZ_MAX_OUTPUT) {
		output_size = RAZE_FUZZ_MAX_OUTPUT;
	}

	packed_size = size - 1U;
	dict_size = pick_dict_size(data[0]);
	extra_dist = (data[0] & 1U) ? 1 : 0;
	solid = (data[0] & 2U) ? 1 : 0;

	output = (unsigned char *)malloc(output_size > 0U ? output_size : 1U);
	if (output == 0) {
		return 0;
	}
	memset(output, 0, output_size > 0U ? output_size : 1U);

	raze_rar5_unpack_ctx_init(&ctx);
	(void)raze_rar5_unpack_ctx_decode_file(
		&ctx,
		(const unsigned char *)data + 1U,
		packed_size,
		output,
		output_size,
		dict_size,
		extra_dist,
		solid
	);
	raze_rar5_unpack_ctx_free(&ctx);

	free(output);
	return 0;
}
