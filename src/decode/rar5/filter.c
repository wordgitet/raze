#include "filter.h"

#include <stdlib.h>
#include <string.h>

static uint32_t read_u32le(const unsigned char *ptr) {
	return (uint32_t)ptr[0] |
		((uint32_t)ptr[1] << 8) |
		((uint32_t)ptr[2] << 16) |
		((uint32_t)ptr[3] << 24);
}

static void write_u32le(unsigned char *ptr, uint32_t value) {
	ptr[0] = (unsigned char)(value & 0xffU);
	ptr[1] = (unsigned char)((value >> 8) & 0xffU);
	ptr[2] = (unsigned char)((value >> 16) & 0xffU);
	ptr[3] = (unsigned char)((value >> 24) & 0xffU);
}

void raze_rar5_filter_queue_init(RazeRar5FilterQueue *queue) {
	if (queue == 0) {
		return;
	}
	queue->ops = 0;
	queue->count = 0;
	queue->cap = 0;
}

void raze_rar5_filter_queue_free(RazeRar5FilterQueue *queue) {
	if (queue == 0) {
		return;
	}
	free(queue->ops);
	queue->ops = 0;
	queue->count = 0;
	queue->cap = 0;
}

int raze_rar5_filter_queue_push(RazeRar5FilterQueue *queue, const RazeRar5FilterOp *op) {
	RazeRar5FilterOp *expanded;
	size_t new_cap;

	if (queue == 0 || op == 0) {
		return 0;
	}
	if (queue->count >= RAZE_RAR5_FILTER_MAX_COUNT) {
		return 0;
	}

	if (queue->count == queue->cap) {
		new_cap = queue->cap == 0 ? 16U : queue->cap * 2U;
		expanded = (RazeRar5FilterOp *)realloc(queue->ops, new_cap * sizeof(*expanded));
		if (expanded == 0) {
			return 0;
		}
		queue->ops = expanded;
		queue->cap = new_cap;
	}

	queue->ops[queue->count++] = *op;
	return 1;
}

static int apply_filter_e8(unsigned char *data, size_t data_size, uint32_t file_offset, int with_e9) {
	size_t cur_pos = 0;
	const uint32_t file_size = 0x1000000U;
	unsigned char cmp_byte2 = with_e9 ? 0xe9U : 0xe8U;

	while (cur_pos + 4U < data_size) {
		unsigned char cur = data[cur_pos++];
		if (cur == 0xe8U || cur == cmp_byte2) {
			uint32_t offset = (uint32_t)((cur_pos + file_offset) % file_size);
			uint32_t addr = read_u32le(data + cur_pos);

			if ((addr & 0x80000000U) != 0U) {
				if (((addr + offset) & 0x80000000U) == 0U) {
					write_u32le(data + cur_pos, addr + file_size);
				}
			} else if (((addr - file_size) & 0x80000000U) != 0U) {
				write_u32le(data + cur_pos, addr - offset);
			}
			cur_pos += 4U;
		}
	}

	return 1;
}

static int apply_filter_arm(unsigned char *data, size_t data_size, uint32_t file_offset) {
	size_t cur_pos;

	for (cur_pos = 0; cur_pos + 3U < data_size; cur_pos += 4U) {
		unsigned char *p = data + cur_pos;
		if (p[3] == 0xebU) {
			uint32_t offset = (uint32_t)p[0] |
				((uint32_t)p[1] << 8) |
				((uint32_t)p[2] << 16);
			offset -= (file_offset + (uint32_t)cur_pos) / 4U;
			p[0] = (unsigned char)offset;
			p[1] = (unsigned char)(offset >> 8);
			p[2] = (unsigned char)(offset >> 16);
		}
	}

	return 1;
}

static int apply_filter_delta(unsigned char *data, size_t data_size, uint32_t channels) {
	unsigned char *tmp;
	uint32_t cur_channel;
	size_t src_pos = 0;

	if (channels == 0U) {
		return 0;
	}

	tmp = (unsigned char *)malloc(data_size);
	if (tmp == 0) {
		return 0;
	}

	for (cur_channel = 0; cur_channel < channels; ++cur_channel) {
		unsigned char prev = 0;
		size_t dest_pos;

		for (dest_pos = cur_channel; dest_pos < data_size; dest_pos += channels) {
			if (src_pos >= data_size) {
				free(tmp);
				return 0;
			}
			prev = (unsigned char)(prev - data[src_pos++]);
			tmp[dest_pos] = prev;
		}
	}

	memcpy(data, tmp, data_size);
	free(tmp);
	return 1;
}

int raze_rar5_apply_filters(
	unsigned char *data,
	size_t data_size,
	const RazeRar5FilterQueue *queue,
	int *unsupported_filter
) {
	size_t i;

	if (unsupported_filter != 0) {
		*unsupported_filter = 0;
	}

	if (data == 0 || queue == 0) {
		return 0;
	}

	for (i = 0; i < queue->count; ++i) {
		const RazeRar5FilterOp *op = &queue->ops[i];
		unsigned char *block;

		if (op->block_length == 0U) {
			continue;
		}
		if (op->block_start > data_size || op->block_length > data_size - op->block_start) {
			return 0;
		}

		block = data + op->block_start;

		switch (op->type) {
			case RAZE_RAR5_FILTER_DELTA:
				if (!apply_filter_delta(block, op->block_length, op->channels)) {
					return 0;
				}
				break;
			case RAZE_RAR5_FILTER_E8:
				if (!apply_filter_e8(block, op->block_length, (uint32_t)op->block_start, 0)) {
					return 0;
				}
				break;
			case RAZE_RAR5_FILTER_E8E9:
				if (!apply_filter_e8(block, op->block_length, (uint32_t)op->block_start, 1)) {
					return 0;
				}
				break;
			case RAZE_RAR5_FILTER_ARM:
				if (!apply_filter_arm(block, op->block_length, (uint32_t)op->block_start)) {
					return 0;
				}
				break;
			default:
				if (unsupported_filter != 0) {
					*unsupported_filter = 1;
				}
				return 0;
		}
	}

	return 1;
}
