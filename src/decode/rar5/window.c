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
	size_t src;
	size_t i;

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

	src = window->pos - distance;
	for (i = 0; i < length; ++i) {
		window->data[window->pos] = window->data[src];
		window->pos += 1;
		src += 1;
	}

	return 1;
}
