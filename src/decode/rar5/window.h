#ifndef RAZE_DECODE_RAR5_WINDOW_H
#define RAZE_DECODE_RAR5_WINDOW_H

#include <stddef.h>
#include <stdint.h>

typedef struct RazeRar5Window {
	unsigned char *data;
	size_t size;
	size_t pos;
} RazeRar5Window;

int raze_rar5_window_init(RazeRar5Window *window, size_t size);
void raze_rar5_window_free(RazeRar5Window *window);

int raze_rar5_window_put_literal(RazeRar5Window *window, unsigned char value);
int raze_rar5_window_copy_match(
	RazeRar5Window *window,
	size_t length,
	size_t distance
);

#endif
