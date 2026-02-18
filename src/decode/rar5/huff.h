#ifndef RAZE_DECODE_RAR5_HUFF_H
#define RAZE_DECODE_RAR5_HUFF_H

#include <stdint.h>

#include "bit_reader.h"

#define RAZE_RAR5_MAX_QUICK_DECODE_BITS 9U
#define RAZE_RAR5_LARGEST_TABLE_SIZE 306U

typedef struct RazeRar5DecodeTable {
	uint32_t max_num;
	uint32_t decode_len[16];
	uint32_t decode_pos[16];
	uint32_t quick_bits;
	unsigned char quick_len[1U << RAZE_RAR5_MAX_QUICK_DECODE_BITS];
	uint16_t quick_num[1U << RAZE_RAR5_MAX_QUICK_DECODE_BITS];
	uint16_t decode_num[RAZE_RAR5_LARGEST_TABLE_SIZE];
} RazeRar5DecodeTable;

void raze_rar5_make_decode_tables(
	const unsigned char *length_table,
	RazeRar5DecodeTable *dec,
	uint32_t size
);

int raze_rar5_decode_number(
	RazeRar5BitReader *reader,
	RazeRar5DecodeTable *dec,
	uint32_t *number
);

#endif
