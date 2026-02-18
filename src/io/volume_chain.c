#include "volume_chain.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static int is_regular_file(const char *path)
{
	struct stat st;

	if (path == 0) {
		return 0;
	}
	if (stat(path, &st) != 0) {
		return 0;
	}
	return S_ISREG(st.st_mode);
}

static int ensure_volume_capacity(RazeVolumeChain *chain, size_t need)
{
	char **expanded;
	size_t cap;

	if (chain == 0) {
		return 0;
	}
	if (chain->capacity >= need) {
		return 1;
	}

	cap = chain->capacity == 0U ? 8U : chain->capacity;
	while (cap < need) {
		if (cap > (SIZE_MAX / 2U)) {
			return 0;
		}
		cap *= 2U;
	}

	expanded = (char **)realloc(chain->paths, cap * sizeof(*expanded));
	if (expanded == 0) {
		return 0;
	}
	chain->paths = expanded;
	chain->capacity = cap;
	return 1;
}

static int append_volume(RazeVolumeChain *chain, const char *path)
{
	size_t len;
	char *copy;

	if (chain == 0 || path == 0) {
		return 0;
	}
	if (!ensure_volume_capacity(chain, chain->count + 1U)) {
		return 0;
	}

	len = strlen(path) + 1U;
	copy = (char *)malloc(len);
	if (copy == 0) {
		return 0;
	}
	memcpy(copy, path, len);

	chain->paths[chain->count++] = copy;
	return 1;
}

static int parse_part_name(const char *path, size_t *prefix_len, int *part_number, int *part_width)
{
	const char *dot_rar;
	const char *dot_part;
	const char *p;
	int number = 0;
	int width = 0;

	if (path == 0 || prefix_len == 0 || part_number == 0 || part_width == 0) {
		return 0;
	}

	dot_rar = strrchr(path, '.');
	if (dot_rar == 0 || strcmp(dot_rar, ".rar") != 0) {
		return 0;
	}

	dot_part = 0;
	{
		const char *scan = dot_rar;
		while (scan > path) {
			scan--;
			if (*scan == '.' && strncmp(scan, ".part", 5) == 0) {
				dot_part = scan;
				break;
			}
		}
	}
	if (dot_part == 0) {
		return 0;
	}

	p = dot_part + 5;
	if (*p < '0' || *p > '9') {
		return 0;
	}
	while (p < dot_rar) {
		if (*p < '0' || *p > '9') {
			return 0;
		}
		if (number > INT_MAX / 10) {
			return 0;
		}
		number = number * 10 + (*p - '0');
		width += 1;
		p++;
	}

	if (number <= 0 || width <= 0) {
		return 0;
	}

	*prefix_len = (size_t)(dot_part - path);
	*part_number = number;
	*part_width = width;
	return 1;
}

void raze_volume_chain_free(RazeVolumeChain *chain)
{
	size_t i;

	if (chain == 0) {
		return;
	}

	for (i = 0; i < chain->count; ++i) {
		free(chain->paths[i]);
	}
	free(chain->paths);
	chain->paths = 0;
	chain->count = 0;
	chain->capacity = 0;
}

RazeStatus raze_volume_chain_discover(const char *first_volume_path, RazeVolumeChain *chain)
{
	size_t prefix_len = 0;
	int part_number = 0;
	int part_width = 0;

	if (first_volume_path == 0 || chain == 0) {
		return RAZE_STATUS_BAD_ARGUMENT;
	}
	memset(chain, 0, sizeof(*chain));

	if (!is_regular_file(first_volume_path)) {
		return RAZE_STATUS_IO;
	}

	if (parse_part_name(first_volume_path, &prefix_len, &part_number, &part_width)) {
		int current = part_number;
		for (;;) {
			char candidate[PATH_MAX];
			int n;

			if (current < 0) {
				break;
			}
			n = snprintf(
				candidate,
				sizeof(candidate),
				"%.*s.part%0*d.rar",
				(int)prefix_len,
				first_volume_path,
				part_width,
				current
			);
			if (n <= 0 || (size_t)n >= sizeof(candidate)) {
				raze_volume_chain_free(chain);
				return RAZE_STATUS_BAD_ARGUMENT;
			}
			if (!is_regular_file(candidate)) {
				break;
			}
			if (!append_volume(chain, candidate)) {
				raze_volume_chain_free(chain);
				return RAZE_STATUS_IO;
			}
			current += 1;
		}
		if (chain->count == 0) {
			raze_volume_chain_free(chain);
			return RAZE_STATUS_IO;
		}
		return RAZE_STATUS_OK;
	}

	if (!append_volume(chain, first_volume_path)) {
		raze_volume_chain_free(chain);
		return RAZE_STATUS_IO;
	}

	{
		const char *dot_rar = strrchr(first_volume_path, '.');
		if (dot_rar != 0 && strcmp(dot_rar, ".rar") == 0) {
			size_t base_len = (size_t)(dot_rar - first_volume_path);
			int index = 0;

			for (;;) {
				char candidate[PATH_MAX];
				int n = snprintf(
					candidate,
					sizeof(candidate),
					"%.*s.r%02d",
					(int)base_len,
					first_volume_path,
					index
				);
				if (n <= 0 || (size_t)n >= sizeof(candidate)) {
					break;
				}
				if (!is_regular_file(candidate)) {
					break;
				}
				if (!append_volume(chain, candidate)) {
					raze_volume_chain_free(chain);
					return RAZE_STATUS_IO;
				}
				index += 1;
			}
		}
	}

	return RAZE_STATUS_OK;
}
