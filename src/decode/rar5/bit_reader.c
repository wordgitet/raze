#include "bit_reader.h"

#include <stddef.h>
#include <string.h>

static uint64_t load_be64_partial(const unsigned char *ptr, size_t avail)
{
	if (ptr == 0) {
		return 0;
	}
	if (avail >= 8U) {
		uint64_t raw;
		memcpy(&raw, ptr, sizeof(raw));
		return __builtin_bswap64(raw);
	}

	uint64_t value = 0;
	size_t i;
	size_t count = avail < 8U ? avail : 8U;

	if (count == 0U) {
		return 0;
	}

	for (i = 0; i < count; ++i) {
		value = (value << 8U) | (uint64_t)ptr[i];
	}

	if (count < 8U) {
		value <<= (8U - count) * 8U;
	}

	return value;
}

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
	size_t advance_bytes;
	unsigned int advance_bits;
	size_t next_byte_pos;
	unsigned int next_bit_pos;

	if (reader == 0) {
		return 0;
	}
	if (reader->bit_pos > 7U || reader->byte_pos > reader->data_size) {
		return 0;
	}

	advance_bytes = (size_t)(bits >> 3U);
	advance_bits = bits & 7U;

	if (advance_bytes > reader->data_size - reader->byte_pos) {
		return 0;
	}
	next_byte_pos = reader->byte_pos + advance_bytes;
	next_bit_pos = reader->bit_pos + advance_bits;
	if (next_bit_pos >= 8U) {
		if (next_byte_pos == reader->data_size) {
			return 0;
		}
		next_byte_pos += 1U;
		next_bit_pos -= 8U;
	}

	if (next_byte_pos > reader->data_size ||
	    (next_byte_pos == reader->data_size && next_bit_pos != 0U)) {
		return 0;
	}

	reader->byte_pos = next_byte_pos;
	reader->bit_pos = next_bit_pos;
	return 1;
}

int raze_rar5_br_read_bits(
	RazeRar5BitReader *reader,
	unsigned int bits,
	uint64_t *value
) {
	uint64_t chunk;

	if (reader == 0 || value == 0 || bits > 56U) {
		return 0;
	}
	if (bits == 0U) {
		*value = 0;
		return 1;
	}
	if (reader->data == 0 || reader->bit_pos > 7U ||
	    reader->byte_pos > reader->data_size) {
		return 0;
	}

	chunk = load_be64_partial(reader->data + reader->byte_pos, reader->data_size - reader->byte_pos);
	if (reader->bit_pos != 0U) {
		chunk <<= reader->bit_pos;
	}
	*value = chunk >> (64U - bits);

	return raze_rar5_br_add_bits(reader, bits);
}

uint16_t raze_rar5_br_peek16(const RazeRar5BitReader *reader) {
	uint32_t bit_field;
	unsigned int shift;
	const unsigned char *p;
	size_t avail;

	if (reader == 0) {
		return 0;
	}
	if (reader->data == 0 || reader->bit_pos > 7U ||
	    reader->byte_pos > reader->data_size) {
		return 0;
	}
	avail = reader->data_size - reader->byte_pos;
	if (avail == 0U) {
		return 0;
	}

	p = reader->data + reader->byte_pos;
	bit_field = 0;
	if (avail >= 1U) {
		bit_field |= (uint32_t)p[0] << 16U;
	}
	if (avail >= 2U) {
		bit_field |= (uint32_t)p[1] << 8U;
	}
	if (avail >= 3U) {
		bit_field |= (uint32_t)p[2];
	}
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
