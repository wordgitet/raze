#include "unpack_v50.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "bit_reader.h"
#include "filter.h"
#include "huff.h"
#include "window.h"

#define RAZE_RAR5_MAX_LZ_MATCH 0x1001U
#define RAZE_RAR5_MAX_INC_LZ_MATCH (RAZE_RAR5_MAX_LZ_MATCH + 3U)
#define RAZE_RAR5_NC 306U
#define RAZE_RAR5_DCB 64U
#define RAZE_RAR5_DCX 80U
#define RAZE_RAR5_LDC 16U
#define RAZE_RAR5_RC 44U
#define RAZE_RAR5_HUFF_TABLE_SIZEB (RAZE_RAR5_NC + RAZE_RAR5_DCB + RAZE_RAR5_RC + RAZE_RAR5_LDC)
#define RAZE_RAR5_HUFF_TABLE_SIZEX (RAZE_RAR5_NC + RAZE_RAR5_DCX + RAZE_RAR5_RC + RAZE_RAR5_LDC)
#define RAZE_RAR5_BC 20U

typedef struct RazeRar5BlockHeader {
	uint32_t block_size;
	uint32_t block_bit_size;
	size_t block_start;
	int last_block_in_file;
	int table_present;
} RazeRar5BlockHeader;

typedef struct RazeRar5BlockTables {
	RazeRar5DecodeTable ld;
	RazeRar5DecodeTable dd;
	RazeRar5DecodeTable ldd;
	RazeRar5DecodeTable rd;
	RazeRar5DecodeTable bd;
} RazeRar5BlockTables;

static int read_bits_u32(RazeRar5BitReader *reader, unsigned int bits, uint32_t *value) {
	uint64_t temp;

	if (!raze_rar5_br_read_bits(reader, bits, &temp)) {
		return 0;
	}
	*value = (uint32_t)temp;
	return 1;
}

static int read_filter_data(RazeRar5BitReader *reader, uint32_t *value) {
	uint32_t byte_count;
	uint32_t out = 0;
	uint32_t i;

	if (!read_bits_u32(reader, 2, &byte_count)) {
		return 0;
	}
	byte_count += 1U;

	for (i = 0; i < byte_count; ++i) {
		uint32_t b;
		if (!read_bits_u32(reader, 8, &b)) {
			return 0;
		}
		out += b << (i * 8U);
	}

	*value = out;
	return 1;
}

static int read_filter(
	RazeRar5BitReader *reader,
	size_t out_pos,
	RazeRar5FilterQueue *queue
) {
	RazeRar5FilterOp op;
	uint32_t rel_start;
	uint32_t block_length;
	uint32_t type;

	if (!read_filter_data(reader, &rel_start)) {
		return 0;
	}
	if (!read_filter_data(reader, &block_length)) {
		return 0;
	}
	if (!read_bits_u32(reader, 3, &type)) {
		return 0;
	}

	op.block_start = out_pos + (size_t)rel_start;
	op.block_length = block_length > RAZE_RAR5_FILTER_MAX_BLOCK_SIZE ? 0U : (size_t)block_length;
	op.type = type;
	op.channels = 1U;

	if (op.type == RAZE_RAR5_FILTER_DELTA) {
		uint32_t channels;
		if (!read_bits_u32(reader, 5, &channels)) {
			return 0;
		}
		op.channels = channels + 1U;
	}

	return raze_rar5_filter_queue_push(queue, &op);
}

static uint32_t slot_to_length(RazeRar5BitReader *reader, uint32_t slot, int *ok) {
	uint32_t lbits;
	uint32_t length = 2U;

	*ok = 0;
	if (slot < 8U) {
		lbits = 0U;
		length += slot;
	} else {
		lbits = slot / 4U - 1U;
		length += (4U | (slot & 3U)) << lbits;
	}

	if (lbits > 0U) {
		uint32_t extra;
		if (!read_bits_u32(reader, lbits, &extra)) {
			return 0;
		}
		length += extra;
	}

	*ok = 1;
	return length;
}

static void insert_old_dist(size_t old_dist[4], size_t distance) {
	old_dist[3] = old_dist[2];
	old_dist[2] = old_dist[1];
	old_dist[1] = old_dist[0];
	old_dist[0] = distance;
}

static int read_block_header(RazeRar5BitReader *reader, RazeRar5BlockHeader *header) {
	uint32_t block_flags;
	uint32_t saved_checksum;
	uint32_t byte_count;
	uint32_t block_size = 0;
	uint32_t check;
	uint32_t i;

	if (!raze_rar5_br_align_byte(reader)) {
		return 0;
	}

	if (!read_bits_u32(reader, 8, &block_flags)) {
		return 0;
	}

	byte_count = ((block_flags >> 3U) & 3U) + 1U;
	if (byte_count == 4U) {
		return 0;
	}

	header->block_bit_size = (block_flags & 7U) + 1U;

	if (!read_bits_u32(reader, 8, &saved_checksum)) {
		return 0;
	}

	for (i = 0; i < byte_count; ++i) {
		uint32_t b;
		if (!read_bits_u32(reader, 8, &b)) {
			return 0;
		}
		block_size += b << (i * 8U);
	}

	check = 0x5aU ^ block_flags ^ block_size ^ (block_size >> 8U) ^ (block_size >> 16U);
	if (((uint8_t)check) != (uint8_t)saved_checksum) {
		return 0;
	}

	header->block_start = reader->byte_pos;
	header->block_size = block_size;
	header->last_block_in_file = (block_flags & 0x40U) != 0U;
	header->table_present = (block_flags & 0x80U) != 0U;
	return 1;
}

static int past_block(const RazeRar5BitReader *reader, const RazeRar5BlockHeader *header) {
	size_t block_end;

	if (header->block_size == 0U) {
		return 1;
	}

	block_end = header->block_start + (size_t)header->block_size - 1U;
	if (reader->byte_pos > block_end) {
		return 1;
	}
	if (reader->byte_pos < block_end) {
		return 0;
	}
	return reader->bit_pos >= header->block_bit_size;
}

static int read_tables(
	RazeRar5BitReader *reader,
	const RazeRar5BlockHeader *header,
	RazeRar5BlockTables *tables,
	int extra_dist
) {
	unsigned char bit_length[RAZE_RAR5_BC];
	unsigned char table[RAZE_RAR5_HUFF_TABLE_SIZEX];
	uint32_t table_size = extra_dist ? RAZE_RAR5_HUFF_TABLE_SIZEX : RAZE_RAR5_HUFF_TABLE_SIZEB;
	uint32_t i;

	(void)header;

	if (!header->table_present) {
		return 1;
	}

	for (i = 0; i < RAZE_RAR5_BC; ++i) {
		uint32_t length;
		if (!read_bits_u32(reader, 4, &length)) {
			return 0;
		}
		if (length == 15U) {
			uint32_t zero_count;
			if (!read_bits_u32(reader, 4, &zero_count)) {
				return 0;
			}
			if (zero_count == 0U) {
				bit_length[i] = 15U;
			} else {
				zero_count += 2U;
				while (zero_count-- > 0U && i < RAZE_RAR5_BC) {
					bit_length[i++] = 0U;
				}
				i--;
			}
		} else {
			bit_length[i] = (unsigned char)length;
		}
	}

	raze_rar5_make_decode_tables(bit_length, &tables->bd, RAZE_RAR5_BC);

	for (i = 0; i < table_size;) {
		uint32_t number;
		if (!raze_rar5_decode_number(reader, &tables->bd, &number)) {
			return 0;
		}
		if (number < 16U) {
			table[i++] = (unsigned char)number;
		} else if (number < 18U) {
			uint32_t n;
			if (number == 16U) {
				if (!read_bits_u32(reader, 3, &n)) {
					return 0;
				}
				n += 3U;
			} else {
				if (!read_bits_u32(reader, 7, &n)) {
					return 0;
				}
				n += 11U;
			}

			if (i == 0U) {
				return 0;
			}
			while (n-- > 0U && i < table_size) {
				table[i] = table[i - 1U];
				i++;
			}
		} else {
			uint32_t n;
			if (number == 18U) {
				if (!read_bits_u32(reader, 3, &n)) {
					return 0;
				}
				n += 3U;
			} else {
				if (!read_bits_u32(reader, 7, &n)) {
					return 0;
				}
				n += 11U;
			}
			while (n-- > 0U && i < table_size) {
				table[i++] = 0U;
			}
		}
	}

	raze_rar5_make_decode_tables(&table[0], &tables->ld, RAZE_RAR5_NC);
	raze_rar5_make_decode_tables(&table[RAZE_RAR5_NC], &tables->dd,
		extra_dist ? RAZE_RAR5_DCX : RAZE_RAR5_DCB);
	raze_rar5_make_decode_tables(&table[RAZE_RAR5_NC + (extra_dist ? RAZE_RAR5_DCX : RAZE_RAR5_DCB)],
		&tables->ldd, RAZE_RAR5_LDC);
	raze_rar5_make_decode_tables(&table[RAZE_RAR5_NC + (extra_dist ? RAZE_RAR5_DCX : RAZE_RAR5_DCB) + RAZE_RAR5_LDC],
		&tables->rd, RAZE_RAR5_RC);

	return 1;
}

RazeStatus raze_rar5_unpack_v50(
	const unsigned char *packed,
	size_t packed_size,
	unsigned char *output,
	size_t output_size,
	int extra_dist
) {
	RazeRar5BitReader reader;
	RazeRar5BlockHeader block;
	RazeRar5BlockTables tables;
	RazeRar5Window window;
	RazeRar5FilterQueue filter_queue;
	size_t old_dist[4];
	uint32_t last_length = 0;
	int tables_read = 0;
	int file_done = 0;
	int unsupported_filter = 0;
	uint32_t i;

	if (packed == 0 || output == 0) {
		return RAZE_STATUS_BAD_ARGUMENT;
	}

	if (!raze_rar5_window_init(&window, output_size)) {
		return RAZE_STATUS_IO;
	}

	raze_rar5_filter_queue_init(&filter_queue);
	for (i = 0; i < 4U; ++i) {
		old_dist[i] = SIZE_MAX;
	}
	memset(&tables, 0, sizeof(tables));

	raze_rar5_br_init(&reader, packed, packed_size);
	if (!read_block_header(&reader, &block)) {
		raze_rar5_filter_queue_free(&filter_queue);
		raze_rar5_window_free(&window);
		return RAZE_STATUS_BAD_ARCHIVE;
	}
	if (!read_tables(&reader, &block, &tables, extra_dist)) {
		raze_rar5_filter_queue_free(&filter_queue);
		raze_rar5_window_free(&window);
		return RAZE_STATUS_BAD_ARCHIVE;
	}
	tables_read = 1;

	while (window.pos < window.size) {
		while (past_block(&reader, &block)) {
			if (block.last_block_in_file) {
				file_done = 1;
				break;
			}
			if (!read_block_header(&reader, &block)) {
				raze_rar5_filter_queue_free(&filter_queue);
				raze_rar5_window_free(&window);
				return RAZE_STATUS_BAD_ARCHIVE;
			}
			if (!read_tables(&reader, &block, &tables, extra_dist)) {
				raze_rar5_filter_queue_free(&filter_queue);
				raze_rar5_window_free(&window);
				return RAZE_STATUS_BAD_ARCHIVE;
			}
			tables_read = 1;
		}
		if (file_done) {
			break;
		}
		if (!tables_read) {
			raze_rar5_filter_queue_free(&filter_queue);
			raze_rar5_window_free(&window);
			return RAZE_STATUS_BAD_ARCHIVE;
		}

		{
			uint32_t main_slot;
			if (!raze_rar5_decode_number(&reader, &tables.ld, &main_slot)) {
				raze_rar5_filter_queue_free(&filter_queue);
				raze_rar5_window_free(&window);
				return RAZE_STATUS_BAD_ARCHIVE;
			}

			if (main_slot < 256U) {
				if (!raze_rar5_window_put_literal(&window, (unsigned char)main_slot)) {
					raze_rar5_filter_queue_free(&filter_queue);
					raze_rar5_window_free(&window);
					return RAZE_STATUS_BAD_ARCHIVE;
				}
				continue;
			}

			if (main_slot >= 262U) {
				int ok;
				uint32_t length = slot_to_length(&reader, main_slot - 262U, &ok);
				size_t distance = 1U;
				uint32_t dist_slot;
				uint32_t dbits;

				if (!ok) {
					raze_rar5_filter_queue_free(&filter_queue);
					raze_rar5_window_free(&window);
					return RAZE_STATUS_BAD_ARCHIVE;
				}
				if (!raze_rar5_decode_number(&reader, &tables.dd, &dist_slot)) {
					raze_rar5_filter_queue_free(&filter_queue);
					raze_rar5_window_free(&window);
					return RAZE_STATUS_BAD_ARCHIVE;
				}

				if (dist_slot < 4U) {
					dbits = 0U;
					distance += dist_slot;
				} else {
					dbits = dist_slot / 2U - 1U;
					distance += (size_t)(2U | (dist_slot & 1U)) << dbits;
				}

				if (dbits > 0U) {
					if (dbits >= 4U) {
						if (dbits > 4U) {
							uint32_t upper;
							if (!read_bits_u32(&reader, dbits - 4U, &upper)) {
								raze_rar5_filter_queue_free(&filter_queue);
								raze_rar5_window_free(&window);
								return RAZE_STATUS_BAD_ARCHIVE;
							}
							distance += ((size_t)upper << 4U);
						}

						{
							uint32_t low_dist;
							if (!raze_rar5_decode_number(&reader, &tables.ldd, &low_dist)) {
								raze_rar5_filter_queue_free(&filter_queue);
								raze_rar5_window_free(&window);
								return RAZE_STATUS_BAD_ARCHIVE;
							}
							distance += low_dist;
						}
					} else {
						uint32_t lower;
						if (!read_bits_u32(&reader, dbits, &lower)) {
							raze_rar5_filter_queue_free(&filter_queue);
							raze_rar5_window_free(&window);
							return RAZE_STATUS_BAD_ARCHIVE;
						}
						distance += lower;
					}
				}

				if (distance > 0x100U) {
					length += 1U;
					if (distance > 0x2000U) {
						length += 1U;
						if (distance > 0x40000U) {
							length += 1U;
						}
					}
				}

				insert_old_dist(old_dist, distance);
				last_length = length;
				if (!raze_rar5_window_copy_match(&window, length, distance)) {
					raze_rar5_filter_queue_free(&filter_queue);
					raze_rar5_window_free(&window);
					return RAZE_STATUS_BAD_ARCHIVE;
				}
				continue;
			}

			if (main_slot == 256U) {
				if (!read_filter(&reader, window.pos, &filter_queue)) {
					raze_rar5_filter_queue_free(&filter_queue);
					raze_rar5_window_free(&window);
					return RAZE_STATUS_BAD_ARCHIVE;
				}
				continue;
			}

			if (main_slot == 257U) {
				if (last_length != 0U) {
					if (!raze_rar5_window_copy_match(&window, last_length, old_dist[0])) {
						raze_rar5_filter_queue_free(&filter_queue);
						raze_rar5_window_free(&window);
						return RAZE_STATUS_BAD_ARCHIVE;
					}
				}
				continue;
			}

			if (main_slot < 262U) {
				uint32_t dist_num = main_slot - 258U;
				size_t distance = old_dist[dist_num];
				uint32_t length_slot;
				uint32_t length;
				int ok;
				size_t j;

				for (j = dist_num; j > 0U; --j) {
					old_dist[j] = old_dist[j - 1U];
				}
				old_dist[0] = distance;

				if (!raze_rar5_decode_number(&reader, &tables.rd, &length_slot)) {
					raze_rar5_filter_queue_free(&filter_queue);
					raze_rar5_window_free(&window);
					return RAZE_STATUS_BAD_ARCHIVE;
				}
				length = slot_to_length(&reader, length_slot, &ok);
				if (!ok) {
					raze_rar5_filter_queue_free(&filter_queue);
					raze_rar5_window_free(&window);
					return RAZE_STATUS_BAD_ARCHIVE;
				}

				last_length = length;
				if (!raze_rar5_window_copy_match(&window, length, distance)) {
					raze_rar5_filter_queue_free(&filter_queue);
					raze_rar5_window_free(&window);
					return RAZE_STATUS_BAD_ARCHIVE;
				}
				continue;
			}

			raze_rar5_filter_queue_free(&filter_queue);
			raze_rar5_window_free(&window);
			return RAZE_STATUS_BAD_ARCHIVE;
		}
	}

	if (window.pos != window.size) {
		raze_rar5_filter_queue_free(&filter_queue);
		raze_rar5_window_free(&window);
		return RAZE_STATUS_BAD_ARCHIVE;
	}

	if (!raze_rar5_apply_filters(window.data, window.size, &filter_queue, &unsupported_filter)) {
		raze_rar5_filter_queue_free(&filter_queue);
		if (unsupported_filter) {
			raze_rar5_window_free(&window);
			return RAZE_STATUS_UNSUPPORTED_FEATURE;
		}
		raze_rar5_window_free(&window);
		return RAZE_STATUS_BAD_ARCHIVE;
	}

	memcpy(output, window.data, window.size);

	raze_rar5_filter_queue_free(&filter_queue);
	raze_rar5_window_free(&window);
	return RAZE_STATUS_OK;
}
