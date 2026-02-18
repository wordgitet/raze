#ifndef RAZE_DECODE_RAR5_FILTER_H
#define RAZE_DECODE_RAR5_FILTER_H

#include <stddef.h>
#include <stdint.h>

#define RAZE_RAR5_FILTER_MAX_COUNT 8192U
#define RAZE_RAR5_FILTER_MAX_BLOCK_SIZE 0x400000U

enum {
	RAZE_RAR5_FILTER_DELTA = 0,
	RAZE_RAR5_FILTER_E8 = 1,
	RAZE_RAR5_FILTER_E8E9 = 2,
	RAZE_RAR5_FILTER_ARM = 3
};

typedef struct RazeRar5FilterOp {
	uint32_t type;
	uint32_t channels;
	size_t block_start;
	size_t block_length;
} RazeRar5FilterOp;

typedef struct RazeRar5FilterQueue {
	RazeRar5FilterOp *ops;
	size_t count;
	size_t cap;
} RazeRar5FilterQueue;

void raze_rar5_filter_queue_init(RazeRar5FilterQueue *queue);
void raze_rar5_filter_queue_free(RazeRar5FilterQueue *queue);
int raze_rar5_filter_queue_push(RazeRar5FilterQueue *queue, const RazeRar5FilterOp *op);

int raze_rar5_apply_filters(
	unsigned char *data,
	size_t data_size,
	const RazeRar5FilterQueue *queue,
	int *unsupported_filter
);

#endif
