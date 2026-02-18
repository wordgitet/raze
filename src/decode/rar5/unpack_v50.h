#ifndef RAZE_DECODE_RAR5_UNPACK_V50_H
#define RAZE_DECODE_RAR5_UNPACK_V50_H

#include <stddef.h>
#include <stdint.h>

#include "raze/raze.h"
#include "huff.h"

RazeStatus raze_rar5_unpack_v50(
	const unsigned char *packed,
	size_t packed_size,
	unsigned char *output,
	size_t output_size,
	int extra_dist
);

typedef struct RazeRar5UnpackCtx {
	RazeRar5DecodeTable ld;
	RazeRar5DecodeTable dd;
	RazeRar5DecodeTable ldd;
	RazeRar5DecodeTable rd;
	RazeRar5DecodeTable bd;
	size_t old_dist[4];
	uint32_t last_length;
	unsigned char *dict;
	size_t dict_capacity;
	size_t dict_write_pos;
	size_t dict_filled;
	size_t dict_size;
	int tables_ready;
	int extra_dist;
	int solid_initialized;
} RazeRar5UnpackCtx;

void raze_rar5_unpack_ctx_init(RazeRar5UnpackCtx *ctx);
void raze_rar5_unpack_ctx_reset_for_new_stream(RazeRar5UnpackCtx *ctx);
void raze_rar5_unpack_ctx_free(RazeRar5UnpackCtx *ctx);

RazeStatus raze_rar5_unpack_ctx_decode_file(
	RazeRar5UnpackCtx *ctx,
	const unsigned char *packed,
	size_t packed_size,
	unsigned char *output,
	size_t output_size,
	size_t dict_size,
	int extra_dist,
	int solid
);

#endif
