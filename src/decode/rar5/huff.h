#ifndef RAZE_DECODE_RAR5_HUFF_H
#define RAZE_DECODE_RAR5_HUFF_H

#include <stddef.h>
#include <stdint.h>

#include "bit_reader.h"

#define RAZE_RAR5_MAX_QUICK_DECODE_BITS 10U
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

	if (__builtin_expect(raze_rar5_br_in_fast16(reader), 1)) {
		if (__builtin_expect(reader->profile_enabled, 0)) {
			reader->profile_fast16_hits += 1U;
		}
		bit_field = (uint32_t)(raze_rar5_br_peek16_fast_unchecked(reader) &
				       0xfffeU);
		if (__builtin_expect(bit_field < dec->decode_len[quick_bits], 1)) {
			uint32_t code = bit_field >> (16U - quick_bits);
			raze_rar5_br_addbits_fast_unchecked(reader,
							    dec->quick_len[code]);
			*number = dec->quick_num[code];
			return 1;
		}

		bits = quick_bits + 1U;
		while (bits < 15U && bit_field >= dec->decode_len[bits]) {
			++bits;
		}

		raze_rar5_br_addbits_fast_unchecked(reader, bits);
		dist = bit_field - dec->decode_len[bits - 1U];
		dist >>= (16U - bits);
		pos = dec->decode_pos[bits] + dist;
		if (pos >= dec->max_num) {
			pos = 0U;
		}
		*number = dec->decode_num[pos];
		return 1;
	}

	bit_field = (uint32_t)(raze_rar5_br_peek16(reader) & 0xfffeU);
	if (__builtin_expect(bit_field < dec->decode_len[quick_bits], 1)) {
		uint32_t code = bit_field >> (16U - quick_bits);
		if (!raze_rar5_br_add_bits(reader, dec->quick_len[code])) {
			return 0;
		}
		*number = dec->quick_num[code];
		return 1;
	}

	bits = quick_bits + 1U;
	while (bits < 15U && bit_field >= dec->decode_len[bits]) {
		++bits;
	}

	if (!raze_rar5_br_add_bits(reader, bits)) {
		return 0;
	}

	dist = bit_field - dec->decode_len[bits - 1U];
	dist >>= (16U - bits);
	pos = dec->decode_pos[bits] + dist;
	if (pos >= dec->max_num) {
		pos = 0U;
	}
	*number = dec->decode_num[pos];
	return 1;
}

#endif
