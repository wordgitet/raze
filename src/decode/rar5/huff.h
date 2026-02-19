#ifndef RAZE_DECODE_RAR5_HUFF_H
#define RAZE_DECODE_RAR5_HUFF_H

#include <stddef.h>
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

static inline int raze_rar5_br_fast_add_bits(
	RazeRar5BitReader *reader,
	unsigned int bits
)
{
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

static inline uint16_t raze_rar5_br_fast_peek16(const RazeRar5BitReader *reader)
{
	uint32_t bit_field;
	unsigned int shift;
	const unsigned char *p;

	if (reader == 0) {
		return 0;
	}
	if (__builtin_expect(reader->bit_pos > 7U ||
		reader->byte_pos >= reader->data_size ||
		reader->data_size - reader->byte_pos < 3U, 0)) {
		/* Fall back to the checked slow path near buffer tail. */
		return raze_rar5_br_peek16(reader);
	}

	p = reader->data + reader->byte_pos;
	bit_field = ((uint32_t)p[0] << 16U) |
		    ((uint32_t)p[1] << 8U) |
		    (uint32_t)p[2];
	shift = 8U - reader->bit_pos;
	bit_field >>= shift;
	return (uint16_t)(bit_field & 0xffffU);
}

static inline int raze_rar5_decode_number(
	RazeRar5BitReader *reader,
	RazeRar5DecodeTable *dec,
	uint32_t *number
)
{
	uint32_t bit_field;
	uint32_t quick_bits;
	uint32_t bits;
	uint32_t dist;
	uint32_t pos;

	if (reader == 0 || dec == 0 || number == 0) {
		return 0;
	}

	quick_bits = dec->quick_bits;
	bit_field = (uint32_t)(raze_rar5_br_fast_peek16(reader) & 0xfffeU);
	if (__builtin_expect(bit_field < dec->decode_len[quick_bits], 1)) {
		uint32_t code = bit_field >> (16U - quick_bits);
		if (!raze_rar5_br_fast_add_bits(reader, dec->quick_len[code])) {
			return 0;
		}
		*number = dec->quick_num[code];
		return 1;
	}

	bits = 15U;
	for (pos = quick_bits + 1U; pos < 15U; ++pos) {
		if (bit_field < dec->decode_len[pos]) {
			bits = pos;
			break;
		}
	}

	if (!raze_rar5_br_fast_add_bits(reader, bits)) {
		return 0;
	}

	dist = bit_field - dec->decode_len[bits - 1U];
	dist >>= (16U - bits);
	pos = dec->decode_pos[bits] + dist;
	if (pos >= dec->max_num) {
		pos = 0;
	}
	*number = dec->decode_num[pos];
	return 1;
}

#endif
