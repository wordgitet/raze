#ifndef RAZE_IO_FS_META_H
#define RAZE_IO_FS_META_H

#include <stdint.h>
#include <sys/types.h>
#include <time.h>

int raze_fs_compute_mode(uint64_t host_os, uint64_t file_attr, int is_dir, mode_t *mode_out);
int raze_fs_apply_mode(const char *path, mode_t mode, int quiet);
int raze_fs_apply_mtime(const char *path, time_t unix_mtime, int quiet);

#endif
