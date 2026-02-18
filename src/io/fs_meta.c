#include "fs_meta.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <utime.h>

#define RAZE_RAR5_HOST_OS_WINDOWS 0U
#define RAZE_RAR5_HOST_OS_UNIX 1U
#define RAZE_WIN_ATTR_READONLY 0x01U

static mode_t get_cached_umask(void) {
    static mode_t cached_umask = (mode_t)-1;

    if (cached_umask == (mode_t)-1) {
        mode_t current = umask(022);
        umask(current);
        cached_umask = current;
    }

    return cached_umask;
}

int raze_fs_compute_mode(uint64_t host_os, uint64_t file_attr, int is_dir, mode_t *mode_out) {
    mode_t mask;

    if (mode_out == 0) {
        return 0;
    }

    if (host_os == RAZE_RAR5_HOST_OS_UNIX) {
        *mode_out = (mode_t)(file_attr & 07777U);
        return 1;
    }

    if (host_os != RAZE_RAR5_HOST_OS_WINDOWS) {
        return 0;
    }

    mask = get_cached_umask();
    if (is_dir) {
        *mode_out = (mode_t)(0777 & ~mask);
    } else if ((file_attr & RAZE_WIN_ATTR_READONLY) != 0) {
        *mode_out = (mode_t)(0444 & ~mask);
    } else {
        *mode_out = (mode_t)(0666 & ~mask);
    }

    return 1;
}

int raze_fs_apply_mode(const char *path, mode_t mode, int quiet) {
    if (path == 0) {
        return 0;
    }

    if (chmod(path, mode) == 0) {
        return 1;
    }

    if (!quiet) {
        fprintf(stderr, "raze: warning: cannot set mode for %s: %s\n", path, strerror(errno));
    }

    return 0;
}

int raze_fs_apply_mtime(const char *path, time_t unix_mtime, int quiet) {
    struct utimbuf times;

    if (path == 0) {
        return 0;
    }

    times.actime = unix_mtime;
    times.modtime = unix_mtime;

    if (utime(path, &times) == 0) {
        return 1;
    }

    if (!quiet) {
        fprintf(stderr, "raze: warning: cannot set mtime for %s: %s\n", path, strerror(errno));
    }

    return 0;
}
