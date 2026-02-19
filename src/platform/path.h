#ifndef RAZE_PLATFORM_PATH_H
#define RAZE_PLATFORM_PATH_H

#include <stddef.h>

const char *raze_platform_path_basename(const char *path);
void raze_platform_path_stem(const char *name, char *out, size_t out_size);

#endif
