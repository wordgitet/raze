#ifndef RAZE_IO_PATH_TRANSFORM_H
#define RAZE_IO_PATH_TRANSFORM_H

#include <stddef.h>

int raze_path_transform_build_root(
	const char *base_output,
	const char *archive_path,
	int ad_mode,
	char *out,
	size_t out_size
);

int raze_path_transform_entry(
	const char *entry_name,
	int strip_paths,
	char *out,
	size_t out_size
);

#endif
