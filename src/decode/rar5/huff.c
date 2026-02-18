#include "huff.h"

#include <string.h>

#define RAZE_RAR5_NC 306U
#define RAZE_RAR5_NC20 298U
#define RAZE_RAR5_NC30 299U

static int br_fast_add_bits(RazeRar5BitReader *reader, unsigned int bits)
{
	size_t advance_bytes;
	unsigned int advance_bits;
	size_t next_byte_pos;
	unsigned int next_bit_pos;

	advance_bytes = (size_t)(bits >> 3U);
	advance_bits = bits & 7U;

	next_byte_pos = reader->byte_pos + advance_bytes;
	next_bit_pos = reader->bit_pos + advance_bits;
	if (next_bit_pos >= 8U) {
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

static uint16_t br_fast_peek16(const RazeRar5BitReader *reader)
{
	uint32_t bit_field;
	unsigned int shift;
	const unsigned char *p;

	if (reader->byte_pos > reader->data_size) {
		return 0;
	}
	p = reader->data + reader->byte_pos;

	bit_field = ((uint32_t)p[0] << 16U) | ((uint32_t)p[1] << 8U) | (uint32_t)p[2];
	shift = 8U - reader->bit_pos;
	bit_field >>= shift;
	return (uint16_t)(bit_field & 0xffffU);
}

void raze_rar5_make_decode_tables(
	const unsigned char *length_table,
	RazeRar5DecodeTable *dec,
	uint32_t size
) {
	uint32_t length_count[16];
	uint32_t copy_decode_pos[16];
	uint32_t upper_limit = 0;
	uint32_t i;
	uint32_t cur_bit_length;
	uint32_t quick_data_size;
	uint32_t code;

	if (length_table == 0 || dec == 0 || size == 0 || size > RAZE_RAR5_LARGEST_TABLE_SIZE) {
		return;
	}

	dec->max_num = size;

	memset(length_count, 0, sizeof(length_count));
	for (i = 0; i < size; ++i) {
		length_count[length_table[i] & 0x0fU] += 1U;
	}
	length_count[0] = 0;

	memset(dec->decode_num, 0, size * sizeof(*dec->decode_num));
	dec->decode_pos[0] = 0;
	dec->decode_len[0] = 0;

	for (i = 1; i < 16U; ++i) {
		uint32_t left_aligned;

		upper_limit += length_count[i];
		left_aligned = upper_limit << (16U - i);
		upper_limit *= 2U;

		dec->decode_len[i] = left_aligned;
		dec->decode_pos[i] = dec->decode_pos[i - 1U] + length_count[i - 1U];
	}

	memcpy(copy_decode_pos, dec->decode_pos, sizeof(copy_decode_pos));

	for (i = 0; i < size; ++i) {
		unsigned char bits = length_table[i] & 0x0fU;
		if (bits != 0U) {
			uint32_t pos = copy_decode_pos[bits];
			if (pos < size) {
				dec->decode_num[pos] = (uint16_t)i;
			}
			copy_decode_pos[bits] += 1U;
		}
	}

	switch (size) {
		case RAZE_RAR5_NC:
		case RAZE_RAR5_NC20:
		case RAZE_RAR5_NC30:
			dec->quick_bits = RAZE_RAR5_MAX_QUICK_DECODE_BITS;
			break;
		default:
			dec->quick_bits =
				RAZE_RAR5_MAX_QUICK_DECODE_BITS > 3U ? RAZE_RAR5_MAX_QUICK_DECODE_BITS - 3U : 0U;
			break;
	}

	quick_data_size = 1U << dec->quick_bits;
	cur_bit_length = 1U;

	for (code = 0; code < quick_data_size; ++code) {
		uint32_t bit_field = code << (16U - dec->quick_bits);
		uint32_t dist;
		uint32_t pos;

		while (cur_bit_length < 16U && bit_field >= dec->decode_len[cur_bit_length]) {
			cur_bit_length += 1U;
		}

		dec->quick_len[code] = (unsigned char)cur_bit_length;
		dist = bit_field - dec->decode_len[cur_bit_length - 1U];
		dist >>= (16U - cur_bit_length);

		if (cur_bit_length < 16U) {
			pos = dec->decode_pos[cur_bit_length] + dist;
			if (pos < size) {
				dec->quick_num[code] = dec->decode_num[pos];
				continue;
			}
		}

		dec->quick_num[code] = 0;
	}
}

int raze_rar5_decode_number(
	RazeRar5BitReader *reader,
	RazeRar5DecodeTable *dec,
	uint32_t *number
) {
	uint32_t bit_field;
	uint32_t bits;
	uint32_t dist;
	uint32_t pos;

	if (reader == 0 || dec == 0 || number == 0 || dec->quick_bits > RAZE_RAR5_MAX_QUICK_DECODE_BITS) {
		return 0;
	}

	bit_field = (uint32_t)(br_fast_peek16(reader) & 0xfffeU);
	if (bit_field < dec->decode_len[dec->quick_bits]) {
		uint32_t code = bit_field >> (16U - dec->quick_bits);
		if (!br_fast_add_bits(reader, dec->quick_len[code])) {
			return 0;
		}
		*number = dec->quick_num[code];
		return 1;
	}

	bits = 15U;
	for (pos = dec->quick_bits + 1U; pos < 15U; ++pos) {
		if (bit_field < dec->decode_len[pos]) {
			bits = pos;
			break;
		}
	}

	if (!br_fast_add_bits(reader, bits)) {
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
