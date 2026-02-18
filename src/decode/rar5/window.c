#include "window.h"

#include <stdlib.h>
#include <string.h>

int raze_rar5_window_init(RazeRar5Window *window, size_t size) {
	if (window == 0) {
		return 0;
	}

	window->data = 0;
	window->size = 0;
	window->pos = 0;

	if (size == 0) {
		return 1;
	}

	window->data = (unsigned char *)malloc(size);
	if (window->data == 0) {
		return 0;
	}

	window->size = size;
	window->pos = 0;
	return 1;
}

void raze_rar5_window_free(RazeRar5Window *window) {
	if (window == 0) {
		return;
	}

	free(window->data);
	window->data = 0;
	window->size = 0;
	window->pos = 0;
}

int raze_rar5_window_put_literal(RazeRar5Window *window, unsigned char value) {
	if (window == 0 || window->data == 0 || window->pos >= window->size) {
		return 0;
	}

	window->data[window->pos++] = value;
	return 1;
}

int raze_rar5_window_copy_match(
	RazeRar5Window *window,
	size_t length,
	size_t distance
) {
	unsigned char *dst;
	const unsigned char *src;
	size_t copied;
	size_t remaining = length;

	if (window == 0 || window->data == 0 || window->pos > window->size) {
		return 0;
	}
	if (window->pos + length > window->size) {
		return 0;
	}

	if (distance == 0 || distance > window->pos) {
		memset(window->data + window->pos, 0, length);
		window->pos += length;
		return 1;
	}

	dst = window->data + window->pos;
	src = dst - distance;

	if (distance == 1U) {
		memset(dst, src[0], length);
		window->pos += length;
		return 1;
	}

	if (distance >= length) {
		memcpy(dst, src, length);
		window->pos += length;
		return 1;
	}

	memcpy(dst, src, distance);
	copied = distance;
	remaining -= distance;

	while (remaining > 0U) {
		size_t chunk = copied;
		if (chunk > remaining) {
			chunk = remaining;
		}
		memcpy(dst + copied, dst, chunk);
		copied += chunk;
		remaining -= chunk;
	}

	window->pos += length;
	return 1;
}
