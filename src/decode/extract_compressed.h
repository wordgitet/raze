#ifndef RAZE_DECODE_EXTRACT_COMPRESSED_H
#define RAZE_DECODE_EXTRACT_COMPRESSED_H

#include <stdio.h>

#include "decode_internal.h"

typedef struct RazeCompressedScratch {
	unsigned char *packed;
	size_t packed_capacity;
	unsigned char *unpacked;
	size_t unpacked_capacity;
} RazeCompressedScratch;

void raze_compressed_scratch_init(RazeCompressedScratch *scratch);
void raze_compressed_scratch_free(RazeCompressedScratch *scratch);

RazeStatus raze_extract_compressed_payload(
	FILE *archive,
	FILE *output,
	const RazeRar5FileHeader *fh,
	RazeCompressedScratch *scratch
);

#endif
