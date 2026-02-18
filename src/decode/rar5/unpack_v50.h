#ifndef RAZE_DECODE_RAR5_UNPACK_V50_H
#define RAZE_DECODE_RAR5_UNPACK_V50_H

#include <stddef.h>

#include "raze/raze.h"

RazeStatus raze_rar5_unpack_v50(
	const unsigned char *packed,
	size_t packed_size,
	unsigned char *output,
	size_t output_size,
	int extra_dist
);

#endif
