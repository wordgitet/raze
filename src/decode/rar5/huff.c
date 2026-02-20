#include "huff.h"

#include <string.h>

#define RAZE_RAR5_NC 306U
#define RAZE_RAR5_NC20 298U
#define RAZE_RAR5_NC30 299U

void raze_rar5_make_decode_tables(
	const unsigned char *length_table,
	RazeRar5DecodeTable *dec,
	uint32_t size
)
{
	uint32_t length_count[16];
	uint32_t copy_decode_pos[16];
	uint32_t upper_limit = 0;
	uint32_t i;
	uint32_t cur_bit_length;
	uint32_t quick_data_size;
	uint32_t code;

	if (length_table == 0 || dec == 0 ||
	    size == 0 || size > RAZE_RAR5_LARGEST_TABLE_SIZE) {
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
		dec->decode_pos[i] = dec->decode_pos[i - 1U] +
					    length_count[i - 1U];
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
		dec->quick_bits = RAZE_RAR5_MAX_QUICK_DECODE_BITS >= 10U ? 10U :
			RAZE_RAR5_MAX_QUICK_DECODE_BITS;
		break;
	default:
		dec->quick_bits = RAZE_RAR5_MAX_QUICK_DECODE_BITS >= 7U ? 7U :
			RAZE_RAR5_MAX_QUICK_DECODE_BITS;
		break;
	}

	quick_data_size = 1U << dec->quick_bits;
	cur_bit_length = 1U;

	for (code = 0; code < quick_data_size; ++code) {
		uint32_t bit_field = code << (16U - dec->quick_bits);
		uint32_t dist;
		uint32_t pos;

		while (cur_bit_length < 16U &&
		       bit_field >= dec->decode_len[cur_bit_length]) {
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
