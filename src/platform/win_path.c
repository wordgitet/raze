#ifdef _WIN32

#include "path.h"

#include <string.h>

const char *raze_platform_path_basename(const char *path)
{
	const char *s;
	const char *last;

	if (path == 0) {
		return "";
	}
	last = path;
	for (s = path; *s != '\0'; ++s) {
		if (*s == '/' || *s == '\\' || *s == ':') {
			last = s + 1;
		}
	}
	return last;
}

void raze_platform_path_stem(const char *name, char *out, size_t out_size)
{
	size_t i;

	if (out == 0 || out_size == 0U) {
		return;
	}
	out[0] = '\0';
	if (name == 0 || name[0] == '\0') {
		return;
	}

	for (i = 0; i + 1U < out_size && name[i] != '\0'; ++i) {
		if (name[i] == '.') {
			break;
		}
		out[i] = name[i];
	}
	out[i] = '\0';
}

#else
typedef int raze_win_path_unused_t;
#endif
