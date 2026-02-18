#ifndef RAZE_DECODE_RAR5_BIT_READER_H
#define RAZE_DECODE_RAR5_BIT_READER_H

#include <stddef.h>
#include <stdint.h>

typedef struct RazeRar5BitReader {
	const unsigned char *data;
	size_t data_size;
	size_t byte_pos;
	unsigned int bit_pos;
} RazeRar5BitReader;

void raze_rar5_br_init(
	RazeRar5BitReader *reader,
	const unsigned char *data,
	size_t data_size
);

int raze_rar5_br_add_bits(RazeRar5BitReader *reader, unsigned int bits);
int raze_rar5_br_read_bits(
	RazeRar5BitReader *reader,
	unsigned int bits,
	uint64_t *value
);
uint16_t raze_rar5_br_peek16(const RazeRar5BitReader *reader);
int raze_rar5_br_align_byte(RazeRar5BitReader *reader);
size_t raze_rar5_br_bit_offset(const RazeRar5BitReader *reader);

#endif
