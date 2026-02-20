#ifndef RAZE_DECODE_RAR5_COPY_KERNELS_H
#define RAZE_DECODE_RAR5_COPY_KERNELS_H

#include <stddef.h>

typedef void (*RazeRar5CopyOverlapFn)(
	unsigned char *dst,
	size_t length,
	size_t distance
);

typedef void (*RazeRar5FillRepeat2Fn)(
	unsigned char *dst,
	size_t length,
	unsigned char b0,
	unsigned char b1
);

typedef void (*RazeRar5FillRepeat3Fn)(
	unsigned char *dst,
	size_t length,
	const unsigned char p[3]
);

typedef void (*RazeRar5FillRepeat4Fn)(
	unsigned char *dst,
	size_t length,
	const unsigned char p[4]
);

typedef struct RazeRar5CopyKernels {
	RazeRar5CopyOverlapFn copy_overlap;
	RazeRar5FillRepeat2Fn fill_repeat2;
	RazeRar5FillRepeat3Fn fill_repeat3;
	RazeRar5FillRepeat4Fn fill_repeat4;
} RazeRar5CopyKernels;

const RazeRar5CopyKernels *raze_rar5_copy_kernels_get(void);

#endif
