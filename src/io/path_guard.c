#include "path_guard.h"

#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

#include "../platform/fs.h"

#define RAZE_PATH_MAX 4096
#define RAZE_RAR5_HOST_OS_WINDOWS 0U

static int is_output_sep(char ch) {
    return ch == '/' || ch == '\\';
}

static int is_absolute_path(const char *path, uint64_t host_os) {
    if (path == 0 || path[0] == '\0') {
        return 0;
    }
    if (path[0] == '/') {
        return 1;
    }
    if (host_os == RAZE_RAR5_HOST_OS_WINDOWS &&
        isalpha((unsigned char)path[0]) &&
        path[1] == ':') {
        return 1;
    }
    return 0;
}

static RazeStatus mkdir_if_needed(const char *path) {
    struct stat st;

    if (path == 0 || path[0] == '\0') {
        return RAZE_STATUS_BAD_ARGUMENT;
    }

    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return RAZE_STATUS_OK;
        }
        return RAZE_STATUS_IO;
    }

    if (raze_platform_fs_mkdir(path) == 0) {
        return RAZE_STATUS_OK;
    }
    if (errno == EEXIST) {
        return RAZE_STATUS_OK;
    }
    return RAZE_STATUS_IO;
}

RazeStatus raze_path_guard_join(
    const char *output_root,
    const char *entry_name,
    uint64_t host_os,
    char *out_path,
    size_t out_path_len
) {
    char normalized[RAZE_PATH_MAX];
    size_t norm_len = 0;
    const char *cursor;

    if (output_root == 0 || entry_name == 0 || out_path == 0 || out_path_len == 0) {
        return RAZE_STATUS_BAD_ARGUMENT;
    }

    if (is_absolute_path(entry_name, host_os)) {
        return RAZE_STATUS_PATH_VIOLATION;
    }

    if (host_os == RAZE_RAR5_HOST_OS_WINDOWS && strchr(entry_name, '\\') != 0) {
        return RAZE_STATUS_PATH_VIOLATION;
    }

    normalized[0] = '\0';
    cursor = entry_name;
    while (*cursor != '\0') {
        const char *start;
        size_t part_len;
        size_t i;
        int only_dots = 1;

        while (*cursor != '\0' && *cursor == '/') {
            cursor++;
        }
        if (*cursor == '\0') {
            break;
        }

        start = cursor;
        while (*cursor != '\0' && *cursor != '/') {
            cursor++;
        }
        part_len = (size_t)(cursor - start);
        if (part_len == 0) {
            continue;
        }

        for (i = 0; i < part_len; ++i) {
            if (start[i] == '\0') {
                return RAZE_STATUS_BAD_ARCHIVE;
            }
            if (start[i] != '.') {
                only_dots = 0;
            }
        }

        if (part_len == 1 && start[0] == '.') {
            continue;
        }
        if (part_len == 2 && start[0] == '.' && start[1] == '.') {
            return RAZE_STATUS_PATH_VIOLATION;
        }
        if (only_dots && part_len > 1) {
            return RAZE_STATUS_PATH_VIOLATION;
        }

        if (norm_len != 0) {
            if (norm_len + 1 >= sizeof(normalized)) {
                return RAZE_STATUS_IO;
            }
            normalized[norm_len++] = '/';
        }

        if (norm_len + part_len >= sizeof(normalized)) {
            return RAZE_STATUS_IO;
        }
        memcpy(normalized + norm_len, start, part_len);
        norm_len += part_len;
        normalized[norm_len] = '\0';
    }

    if (norm_len == 0) {
        return RAZE_STATUS_PATH_VIOLATION;
    }

    {
        size_t root_len = strlen(output_root);
        int need_sep = root_len > 0 && !is_output_sep(output_root[root_len - 1]);
        size_t total_len = root_len + (need_sep ? 1U : 0U) + norm_len;
        if (total_len + 1 > out_path_len) {
            return RAZE_STATUS_IO;
        }
        memcpy(out_path, output_root, root_len);
        if (need_sep) {
            out_path[root_len++] = '/';
        }
        memcpy(out_path + root_len, normalized, norm_len);
        out_path[root_len + norm_len] = '\0';
    }

    return RAZE_STATUS_OK;
}

RazeStatus raze_path_guard_make_dirs(const char *dir_path) {
    char tmp[RAZE_PATH_MAX];
    size_t len;
    size_t i;
    RazeStatus status;

    if (dir_path == 0) {
        return RAZE_STATUS_BAD_ARGUMENT;
    }

    len = strlen(dir_path);
    if (len == 0) {
        return RAZE_STATUS_OK;
    }
    if (len >= sizeof(tmp)) {
        return RAZE_STATUS_IO;
    }

    memcpy(tmp, dir_path, len + 1);

    for (i = 1; i < len; ++i) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            if (tmp[0] != '\0') {
                status = mkdir_if_needed(tmp);
                if (status != RAZE_STATUS_OK) {
                    return status;
                }
            }
            tmp[i] = '/';
        }
    }

    return mkdir_if_needed(tmp);
}

RazeStatus raze_path_guard_make_parent_dirs(const char *file_path) {
    char tmp[RAZE_PATH_MAX];
    char *slash;

    if (file_path == 0) {
        return RAZE_STATUS_BAD_ARGUMENT;
    }

    if (strlen(file_path) >= sizeof(tmp)) {
        return RAZE_STATUS_IO;
    }

    strcpy(tmp, file_path);
    slash = strrchr(tmp, '/');
    if (slash == 0) {
        return RAZE_STATUS_OK;
    }
    *slash = '\0';
    if (tmp[0] == '\0') {
        return RAZE_STATUS_OK;
    }
    return raze_path_guard_make_dirs(tmp);
}
