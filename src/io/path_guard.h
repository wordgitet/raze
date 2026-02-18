#ifndef RAZE_IO_PATH_GUARD_H
#define RAZE_IO_PATH_GUARD_H

#include <stddef.h>
#include <stdint.h>

#include "raze/raze.h"

RazeStatus raze_path_guard_join(
    const char *output_root,
    const char *entry_name,
    uint64_t host_os,
    char *out_path,
    size_t out_path_len
);

RazeStatus raze_path_guard_make_dirs(const char *dir_path);
RazeStatus raze_path_guard_make_parent_dirs(const char *file_path);

#endif
