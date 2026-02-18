#include "unpack_v50.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bit_reader.h"
#include "filter.h"
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

static int read_bits_u32(RazeRar5BitReader *reader, unsigned int bits, uint32_t *value)
{
	uint64_t temp;

	if (!raze_rar5_br_read_bits(reader, bits, &temp)) {
		return 0;
	}
	*value = (uint32_t)temp;
	return 1;
}

static int read_filter_data(RazeRar5BitReader *reader, uint32_t *value)
{
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

static int read_filter(RazeRar5BitReader *reader, size_t out_pos, RazeRar5FilterQueue *queue)
{
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

static uint32_t slot_to_length(RazeRar5BitReader *reader, uint32_t slot, int *ok)
{
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

static void insert_old_dist(size_t old_dist[4], size_t distance)
{
	old_dist[3] = old_dist[2];
	old_dist[2] = old_dist[1];
	old_dist[1] = old_dist[0];
	old_dist[0] = distance;
}

static int read_block_header(RazeRar5BitReader *reader, RazeRar5BlockHeader *header)
{
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

static int past_block(const RazeRar5BitReader *reader, const RazeRar5BlockHeader *header)
{
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
	RazeRar5UnpackCtx *ctx,
	int extra_dist
)
{
	unsigned char bit_length[RAZE_RAR5_BC];
	unsigned char table[RAZE_RAR5_HUFF_TABLE_SIZEX];
	uint32_t table_size = extra_dist ? RAZE_RAR5_HUFF_TABLE_SIZEX : RAZE_RAR5_HUFF_TABLE_SIZEB;
	uint32_t i;

	if (!header->table_present) {
		return ctx->tables_ready;
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

	raze_rar5_make_decode_tables(bit_length, &ctx->bd, RAZE_RAR5_BC);

	for (i = 0; i < table_size;) {
		uint32_t number;
		if (!raze_rar5_decode_number(reader, &ctx->bd, &number)) {
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

	raze_rar5_make_decode_tables(&table[0], &ctx->ld, RAZE_RAR5_NC);
	raze_rar5_make_decode_tables(
		&table[RAZE_RAR5_NC],
		&ctx->dd,
		extra_dist ? RAZE_RAR5_DCX : RAZE_RAR5_DCB
	);
	raze_rar5_make_decode_tables(
		&table[RAZE_RAR5_NC + (extra_dist ? RAZE_RAR5_DCX : RAZE_RAR5_DCB)],
		&ctx->ldd,
		RAZE_RAR5_LDC
	);
	raze_rar5_make_decode_tables(
		&table[RAZE_RAR5_NC + (extra_dist ? RAZE_RAR5_DCX : RAZE_RAR5_DCB) + RAZE_RAR5_LDC],
		&ctx->rd,
		RAZE_RAR5_RC
	);
	ctx->tables_ready = 1;
	return 1;
}

static int ensure_history_capacity(RazeRar5UnpackCtx *ctx, size_t need)
{
	unsigned char *expanded;

	if (need <= ctx->history_capacity) {
		return 1;
	}
	expanded = (unsigned char *)realloc(ctx->history, need);
	if (expanded == 0) {
		return 0;
	}
	ctx->history = expanded;
	ctx->history_capacity = need;
	return 1;
}

static void update_history(
	RazeRar5UnpackCtx *ctx,
	const unsigned char *data,
	size_t data_size,
	size_t dict_size
)
{
	size_t keep;

	if (dict_size == 0U || data == 0 || data_size == 0U) {
		ctx->history_size = 0U;
		ctx->dict_size = dict_size;
		return;
	}

	keep = data_size < dict_size ? data_size : dict_size;
	if (!ensure_history_capacity(ctx, keep)) {
		ctx->history_size = 0U;
		ctx->dict_size = dict_size;
		return;
	}

	memcpy(ctx->history, data + (data_size - keep), keep);
	ctx->history_size = keep;
	ctx->dict_size = dict_size;
}

void raze_rar5_unpack_ctx_reset_for_new_stream(RazeRar5UnpackCtx *ctx)
{
	uint32_t i;

	if (ctx == 0) {
		return;
	}

	ctx->tables_ready = 0;
	memset(&ctx->ld, 0, sizeof(ctx->ld));
	memset(&ctx->dd, 0, sizeof(ctx->dd));
	memset(&ctx->ldd, 0, sizeof(ctx->ldd));
	memset(&ctx->rd, 0, sizeof(ctx->rd));
	memset(&ctx->bd, 0, sizeof(ctx->bd));
	for (i = 0; i < 4U; ++i) {
		ctx->old_dist[i] = SIZE_MAX;
	}
	ctx->last_length = 0U;
	ctx->history_size = 0U;
	ctx->dict_size = 0U;
	ctx->extra_dist = 0;
	ctx->solid_initialized = 0;
}

void raze_rar5_unpack_ctx_init(RazeRar5UnpackCtx *ctx)
{
	if (ctx == 0) {
		return;
	}

	memset(ctx, 0, sizeof(*ctx));
	raze_rar5_unpack_ctx_reset_for_new_stream(ctx);
}

void raze_rar5_unpack_ctx_free(RazeRar5UnpackCtx *ctx)
{
	if (ctx == 0) {
		return;
	}

	free(ctx->history);
	ctx->history = 0;
	ctx->history_size = 0;
	ctx->history_capacity = 0;
	raze_rar5_unpack_ctx_reset_for_new_stream(ctx);
}

RazeStatus raze_rar5_unpack_ctx_decode_file(
	RazeRar5UnpackCtx *ctx,
	const unsigned char *packed,
	size_t packed_size,
	unsigned char *output,
	size_t output_size,
	size_t dict_size,
	int extra_dist,
	int solid
)
{
	RazeRar5BitReader reader;
	RazeRar5BlockHeader block;
	RazeRar5Window window;
	RazeRar5FilterQueue filter_queue;
	size_t prefix_len = 0U;
	size_t window_size = 0U;
	int file_done = 0;
	int unsupported_filter = 0;
	RazeStatus status = RAZE_STATUS_OK;

	if (ctx == 0 || packed == 0 || output == 0) {
		return RAZE_STATUS_BAD_ARGUMENT;
	}

	if (!solid) {
		raze_rar5_unpack_ctx_reset_for_new_stream(ctx);
	} else if (!ctx->solid_initialized) {
		raze_rar5_unpack_ctx_reset_for_new_stream(ctx);
	} else {
		if (ctx->extra_dist != extra_dist) {
			raze_rar5_unpack_ctx_reset_for_new_stream(ctx);
			return RAZE_STATUS_BAD_ARCHIVE;
		}
		if (ctx->dict_size != 0U && dict_size != 0U && ctx->dict_size != dict_size) {
			raze_rar5_unpack_ctx_reset_for_new_stream(ctx);
			return RAZE_STATUS_BAD_ARCHIVE;
		}
	}

	if (solid && ctx->solid_initialized && dict_size > 0U) {
		prefix_len = ctx->history_size < dict_size ? ctx->history_size : dict_size;
	}
	if (output_size > SIZE_MAX - prefix_len) {
		raze_rar5_unpack_ctx_reset_for_new_stream(ctx);
		return RAZE_STATUS_BAD_ARCHIVE;
	}
	window_size = prefix_len + output_size;

	if (packed_size == 0U && output_size == 0U) {
		if (solid) {
			update_history(ctx, ctx->history, ctx->history_size, dict_size);
			ctx->extra_dist = extra_dist;
			ctx->solid_initialized = 1;
		}
		return RAZE_STATUS_OK;
	}
	if (packed_size == 0U || (output_size > 0U && window_size == prefix_len)) {
		raze_rar5_unpack_ctx_reset_for_new_stream(ctx);
		return RAZE_STATUS_BAD_ARCHIVE;
	}

	if (!raze_rar5_window_init(&window, window_size)) {
		return RAZE_STATUS_IO;
	}
	if (prefix_len > 0U) {
		memcpy(window.data, ctx->history + (ctx->history_size - prefix_len), prefix_len);
	}
	window.pos = prefix_len;

	raze_rar5_filter_queue_init(&filter_queue);
	raze_rar5_br_init(&reader, packed, packed_size);
	if (!read_block_header(&reader, &block)) {
		status = RAZE_STATUS_BAD_ARCHIVE;
		goto done;
	}
	if (!read_tables(&reader, &block, ctx, extra_dist)) {
		status = RAZE_STATUS_BAD_ARCHIVE;
		goto done;
	}

	while (window.pos < window.size) {
		while (past_block(&reader, &block)) {
			if (block.last_block_in_file) {
				file_done = 1;
				break;
			}
			if (!read_block_header(&reader, &block)) {
				status = RAZE_STATUS_BAD_ARCHIVE;
				goto done;
			}
			if (!read_tables(&reader, &block, ctx, extra_dist)) {
				status = RAZE_STATUS_BAD_ARCHIVE;
				goto done;
			}
		}
		if (file_done) {
			break;
		}
		if (!ctx->tables_ready) {
			status = RAZE_STATUS_BAD_ARCHIVE;
			goto done;
		}

		{
			uint32_t main_slot;
			if (!raze_rar5_decode_number(&reader, &ctx->ld, &main_slot)) {
				status = RAZE_STATUS_BAD_ARCHIVE;
				goto done;
			}

			if (main_slot < 256U) {
				if (!raze_rar5_window_put_literal(&window, (unsigned char)main_slot)) {
					status = RAZE_STATUS_BAD_ARCHIVE;
					goto done;
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
					status = RAZE_STATUS_BAD_ARCHIVE;
					goto done;
				}
				if (!raze_rar5_decode_number(&reader, &ctx->dd, &dist_slot)) {
					status = RAZE_STATUS_BAD_ARCHIVE;
					goto done;
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
								status = RAZE_STATUS_BAD_ARCHIVE;
								goto done;
							}
							distance += ((size_t)upper << 4U);
						}

						{
							uint32_t low_dist;
							if (!raze_rar5_decode_number(&reader, &ctx->ldd, &low_dist)) {
								status = RAZE_STATUS_BAD_ARCHIVE;
								goto done;
							}
							distance += low_dist;
						}
					} else {
						uint32_t lower;
						if (!read_bits_u32(&reader, dbits, &lower)) {
							status = RAZE_STATUS_BAD_ARCHIVE;
							goto done;
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

				insert_old_dist(ctx->old_dist, distance);
				ctx->last_length = length;
				if (!raze_rar5_window_copy_match(&window, length, distance)) {
					status = RAZE_STATUS_BAD_ARCHIVE;
					goto done;
				}
				continue;
			}

			if (main_slot == 256U) {
				size_t file_pos = window.pos >= prefix_len ? window.pos - prefix_len : 0U;
				if (!read_filter(&reader, file_pos, &filter_queue)) {
					status = RAZE_STATUS_BAD_ARCHIVE;
					goto done;
				}
				continue;
			}

			if (main_slot == 257U) {
				if (ctx->last_length != 0U) {
					if (!raze_rar5_window_copy_match(&window, ctx->last_length, ctx->old_dist[0])) {
						status = RAZE_STATUS_BAD_ARCHIVE;
						goto done;
					}
				}
				continue;
			}

			if (main_slot < 262U) {
				uint32_t dist_num = main_slot - 258U;
				size_t distance = ctx->old_dist[dist_num];
				uint32_t length_slot;
				uint32_t length;
				int ok;
				size_t j;

				for (j = dist_num; j > 0U; --j) {
					ctx->old_dist[j] = ctx->old_dist[j - 1U];
				}
				ctx->old_dist[0] = distance;

				if (!raze_rar5_decode_number(&reader, &ctx->rd, &length_slot)) {
					status = RAZE_STATUS_BAD_ARCHIVE;
					goto done;
				}
				length = slot_to_length(&reader, length_slot, &ok);
				if (!ok) {
					status = RAZE_STATUS_BAD_ARCHIVE;
					goto done;
				}

				ctx->last_length = length;
				if (!raze_rar5_window_copy_match(&window, length, distance)) {
					status = RAZE_STATUS_BAD_ARCHIVE;
					goto done;
				}
				continue;
			}

			status = RAZE_STATUS_BAD_ARCHIVE;
			goto done;
		}
	}

	if (window.pos != window.size) {
		status = RAZE_STATUS_BAD_ARCHIVE;
		goto done;
	}

	if (output_size > 0U) {
		memcpy(output, window.data + prefix_len, output_size);
	}
	if (!raze_rar5_apply_filters(output, output_size, &filter_queue, &unsupported_filter)) {
		if (unsupported_filter) {
			status = RAZE_STATUS_UNSUPPORTED_FEATURE;
		} else {
			status = RAZE_STATUS_BAD_ARCHIVE;
		}
		goto done;
	}

	if (solid) {
		update_history(ctx, window.data, window.size, dict_size);
		ctx->extra_dist = extra_dist;
		ctx->solid_initialized = 1;
	} else {
		ctx->solid_initialized = 0;
	}

done:
	raze_rar5_filter_queue_free(&filter_queue);
	raze_rar5_window_free(&window);
	if (status != RAZE_STATUS_OK) {
		raze_rar5_unpack_ctx_reset_for_new_stream(ctx);
	}
	return status;
}

RazeStatus raze_rar5_unpack_v50(
	const unsigned char *packed,
	size_t packed_size,
	unsigned char *output,
	size_t output_size,
	int extra_dist
)
{
	RazeRar5UnpackCtx ctx;
	RazeStatus status;

	raze_rar5_unpack_ctx_init(&ctx);
	status = raze_rar5_unpack_ctx_decode_file(
		&ctx,
		packed,
		packed_size,
		output,
		output_size,
		0U,
		extra_dist,
		0
	);
	raze_rar5_unpack_ctx_free(&ctx);
	return status;
}
