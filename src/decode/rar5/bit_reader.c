#include "bit_reader.h"

#include <string.h>

void raze_rar5_br_init(
	RazeRar5BitReader *reader,
	const unsigned char *data,
	size_t data_size
) {
	if (reader == 0) {
		return;
	}

	reader->data = data;
	reader->data_size = data_size;
	reader->byte_pos = 0;
	reader->bit_pos = 0;
}

size_t raze_rar5_br_bit_offset(const RazeRar5BitReader *reader) {
	if (reader == 0) {
		return 0;
	}

	return reader->byte_pos * 8U + (size_t)reader->bit_pos;
}

int raze_rar5_br_add_bits(RazeRar5BitReader *reader, unsigned int bits) {
	size_t total_bits;
	size_t next_bits;

	if (reader == 0) {
		return 0;
	}

	total_bits = reader->data_size * 8U;
	next_bits = raze_rar5_br_bit_offset(reader) + (size_t)bits;
	if (next_bits > total_bits) {
		return 0;
	}

	reader->byte_pos = next_bits / 8U;
	reader->bit_pos = (unsigned int)(next_bits % 8U);
	return 1;
}

int raze_rar5_br_read_bits(
	RazeRar5BitReader *reader,
	unsigned int bits,
	uint64_t *value
) {
	uint64_t out = 0;
	unsigned int i;

	if (reader == 0 || value == 0 || bits > 56U) {
		return 0;
	}

	for (i = 0; i < bits; ++i) {
		unsigned char cur;
		unsigned int bit;

		if (reader->byte_pos >= reader->data_size) {
			return 0;
		}

		cur = reader->data[reader->byte_pos];
		bit = (cur >> (7U - reader->bit_pos)) & 1U;
		out = (out << 1U) | (uint64_t)bit;

		reader->bit_pos += 1U;
		if (reader->bit_pos == 8U) {
			reader->bit_pos = 0;
			reader->byte_pos += 1U;
		}
	}

	*value = out;
	return 1;
}

uint16_t raze_rar5_br_peek16(const RazeRar5BitReader *reader) {
	uint32_t bit_field;
	unsigned int shift;
	unsigned char b0 = 0;
	unsigned char b1 = 0;
	unsigned char b2 = 0;

	if (reader == 0) {
		return 0;
	}

	if (reader->byte_pos < reader->data_size) {
		b0 = reader->data[reader->byte_pos];
	}
	if (reader->byte_pos + 1U < reader->data_size) {
		b1 = reader->data[reader->byte_pos + 1U];
	}
	if (reader->byte_pos + 2U < reader->data_size) {
		b2 = reader->data[reader->byte_pos + 2U];
	}

	bit_field = ((uint32_t)b0 << 16U) | ((uint32_t)b1 << 8U) | (uint32_t)b2;
	shift = 8U - reader->bit_pos;
	bit_field >>= shift;
	return (uint16_t)(bit_field & 0xffffU);
}

int raze_rar5_br_align_byte(RazeRar5BitReader *reader) {
	unsigned int align;

	if (reader == 0) {
		return 0;
	}

	align = (8U - reader->bit_pos) & 7U;
	return raze_rar5_br_add_bits(reader, align);
}
