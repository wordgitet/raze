#include "path_transform.h"

#include <stdio.h>
#include <string.h>

#include "../platform/path.h"

int raze_path_transform_build_root(
	const char *base_output,
	const char *archive_path,
	int ad_mode,
	char *out,
	size_t out_size
)
{
	char name[512];
	const char *base;

	if (base_output == 0 || out == 0 || out_size == 0U) {
		return 0;
	}

	if (ad_mode == 0) {
		return snprintf(out, out_size, "%s", base_output) < (int)out_size;
	}

	base = raze_platform_path_basename(archive_path != 0 ? archive_path : "");
	if (base == 0 || base[0] == '\0') {
		base = "archive";
	}
	if (ad_mode == 1) {
		raze_platform_path_stem(base, name, sizeof(name));
		if (name[0] == '\0') {
			snprintf(name, sizeof(name), "%s", "archive");
		}
		return snprintf(out, out_size, "%s/%s", base_output, name) <
		       (int)out_size;
	}
	if (ad_mode == 2) {
		return snprintf(out, out_size, "%s/%s", base_output, base) <
		       (int)out_size;
	}

	return 0;
}

int raze_path_transform_entry(
	const char *entry_name,
	int strip_paths,
	char *out,
	size_t out_size
)
{
	const char *src;

	if (entry_name == 0 || out == 0 || out_size == 0U) {
		return 0;
	}

	src = entry_name;
	if (strip_paths) {
		src = raze_platform_path_basename(entry_name);
	}
	if (src == 0 || src[0] == '\0') {
		src = "unnamed";
	}
	return snprintf(out, out_size, "%s", src) < (int)out_size;
}
