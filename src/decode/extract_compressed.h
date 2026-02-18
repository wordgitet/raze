#ifndef RAZE_DECODE_EXTRACT_COMPRESSED_H
#define RAZE_DECODE_EXTRACT_COMPRESSED_H

#include <stdio.h>

#include "decode_internal.h"

RazeStatus raze_extract_compressed_payload(
	FILE *archive,
	FILE *output,
	const RazeRar5FileHeader *fh
);

#endif
