#ifndef RAZE_DECODE_EXTRACT_COMPRESSED_H
#define RAZE_DECODE_EXTRACT_COMPRESSED_H

#include <stdio.h>

#include "decode_internal.h"
#include "rar5/unpack_v50.h"

typedef struct RazeCompressedScratch {
	unsigned char *packed;
	size_t packed_capacity;
	unsigned char *decrypted_packed;
	size_t decrypted_packed_capacity;
	unsigned char *unpacked;
	size_t unpacked_capacity;
	RazeRar5UnpackCtx unpack_ctx;
} RazeCompressedScratch;

void raze_compressed_scratch_init(RazeCompressedScratch *scratch);
void raze_compressed_scratch_free(RazeCompressedScratch *scratch);
void raze_compressed_scratch_reset_solid_stream(RazeCompressedScratch *scratch);

RazeStatus raze_extract_compressed_payload(
	FILE *archive,
	FILE *output,
	const RazeRar5FileHeader *fh,
	RazeCompressedScratch *scratch,
	int solid_stream,
	const char *password,
	int password_present
);

#endif
