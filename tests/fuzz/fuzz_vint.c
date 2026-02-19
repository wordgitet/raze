#include "fuzz_common.h"

#include <stddef.h>
#include <stdint.h>

#include "../../src/format/rar5/vint.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	size_t i;
	size_t consumed = 0;
	uint64_t value = 0;

	if (data == 0 || size == 0 || size > RAZE_FUZZ_MAX_INPUT) {
		return 0;
	}

	for (i = 0; i < size; ++i) {
		(void)raze_vint_decode(
			(const unsigned char *)data + i,
			size - i,
			&consumed,
			&value
		);
	}

	for (i = 1; i <= 10U && i <= size; ++i) {
		(void)raze_vint_decode(
			(const unsigned char *)data,
			i,
			&consumed,
			&value
		);
	}

	return 0;
}
