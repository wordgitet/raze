#include "extract_store.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include "../checksum/crc32.h"
#include "../cli/overwrite_prompt.h"
#include "../format/rar5/block_reader.h"
#include "../format/rar5/file_header.h"
#include "../format/rar5/vint.h"
#include "../io/fs_meta.h"
#include "../io/path_guard.h"
#include "decode_internal.h"
#include "extract_compressed.h"

#define RAZE_RAR5_HEAD_MAIN 1U
#define RAZE_RAR5_HEAD_FILE 2U
#define RAZE_RAR5_HEAD_SERVICE 3U
#define RAZE_RAR5_HEAD_CRYPT 4U
#define RAZE_RAR5_HEAD_ENDARC 5U

#define RAZE_RAR5_MHFL_VOLUME 0x0001U
#define RAZE_RAR5_MHFL_SOLID 0x0004U

typedef struct PendingDirMeta {
    char *path;
    int has_mode;
    mode_t mode;
    int has_mtime;
    time_t mtime;
} PendingDirMeta;

typedef struct PendingDirMetaList {
    PendingDirMeta *items;
    size_t count;
    size_t capacity;
} PendingDirMetaList;

static int skip_forward(FILE *file, uint64_t bytes) {
    while (bytes > 0) {
        long chunk;
        if (bytes > (uint64_t)LONG_MAX) {
            chunk = LONG_MAX;
        } else {
            chunk = (long)bytes;
        }
        if (fseek(file, chunk, SEEK_CUR) != 0) {
            return 0;
        }
        bytes -= (uint64_t)chunk;
    }
    return 1;
}

static void pending_dir_meta_list_free(PendingDirMetaList *list) {
    size_t i;

    if (list == 0) {
        return;
    }

    for (i = 0; i < list->count; ++i) {
        free(list->items[i].path);
    }
    free(list->items);
    list->items = 0;
    list->count = 0;
    list->capacity = 0;
}

static RazeStatus pending_dir_meta_list_add(
    PendingDirMetaList *list,
    const char *path,
    int has_mode,
    mode_t mode,
    int has_mtime,
    time_t mtime
) {
    PendingDirMeta *expanded;
    size_t path_len;

    if (list == 0 || path == 0) {
        return RAZE_STATUS_BAD_ARGUMENT;
    }

    if (list->count == list->capacity) {
        size_t new_capacity = list->capacity == 0 ? 8U : list->capacity * 2U;
        expanded = (PendingDirMeta *)realloc(list->items, new_capacity * sizeof(*expanded));
        if (expanded == 0) {
            return RAZE_STATUS_IO;
        }
        list->items = expanded;
        list->capacity = new_capacity;
    }

    path_len = strlen(path) + 1U;
    list->items[list->count].path = (char *)malloc(path_len);
    if (list->items[list->count].path == 0) {
        return RAZE_STATUS_IO;
    }
    memcpy(list->items[list->count].path, path, path_len);
    list->items[list->count].has_mode = has_mode;
    list->items[list->count].mode = mode;
    list->items[list->count].has_mtime = has_mtime;
    list->items[list->count].mtime = mtime;
    list->count += 1;

    return RAZE_STATUS_OK;
}

static void apply_entry_metadata(const RazeRar5FileHeader *fh, const char *path, int quiet) {
    mode_t mode;

    if (fh == 0 || path == 0) {
        return;
    }

    if (raze_fs_compute_mode(fh->host_os, fh->file_attr, fh->is_dir, &mode)) {
        raze_fs_apply_mode(path, mode, quiet);
    }

    if (fh->mtime_present) {
        raze_fs_apply_mtime(path, (time_t)fh->unix_mtime, quiet);
    }
}

static void apply_pending_dir_metadata(const PendingDirMetaList *list, int quiet) {
    size_t i;

    if (list == 0) {
        return;
    }

    for (i = 0; i < list->count; ++i) {
        const PendingDirMeta *item = &list->items[i];

        if (item->has_mode) {
            raze_fs_apply_mode(item->path, item->mode, quiet);
        }
        if (item->has_mtime) {
            raze_fs_apply_mtime(item->path, item->mtime, quiet);
        }
    }
}

static RazeStatus ensure_supported_file(const RazeRar5FileHeader *fh) {
    if (fh == 0) {
        return RAZE_STATUS_BAD_ARGUMENT;
    }
    if (fh->split_before || fh->split_after) {
        return RAZE_STATUS_UNSUPPORTED_FEATURE;
    }
    if ((fh->file_flags & RAZE_RAR5_FHFL_UNPUNKNOWN) != 0) {
        return RAZE_STATUS_UNSUPPORTED_FEATURE;
    }
    if (fh->solid) {
        return RAZE_STATUS_UNSUPPORTED_FEATURE;
    }
    if (fh->encrypted) {
        return RAZE_STATUS_UNSUPPORTED_FEATURE;
    }
    if (fh->method > 5) {
        return RAZE_STATUS_UNSUPPORTED_FEATURE;
    }
    if (fh->comp_version > 1) {
        return RAZE_STATUS_UNSUPPORTED_FEATURE;
    }
    if (fh->host_os != RAZE_RAR5_HOST_OS_WINDOWS &&
        fh->host_os != RAZE_RAR5_HOST_OS_UNIX) {
        return RAZE_STATUS_UNSUPPORTED_FEATURE;
    }
    if (!fh->is_dir && fh->method == 0 && fh->pack_size != fh->unp_size) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }
    if (fh->method != 0 && fh->dict_size_bytes == 0) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }
    return RAZE_STATUS_OK;
}

static RazeStatus copy_store_payload(
    FILE *archive,
    FILE *output,
    uint64_t size,
    int crc32_present,
    uint32_t expected_crc32
) {
    unsigned char buf[1U << 16];
    uint64_t remaining = size;
    uint32_t crc = raze_crc32_init();

    while (remaining > 0) {
        size_t want = sizeof(buf);
        size_t nread;
        size_t nwritten;

        if (remaining < want) {
            want = (size_t)remaining;
        }

        nread = fread(buf, 1, want, archive);
        if (nread == 0) {
            if (feof(archive)) {
                return RAZE_STATUS_BAD_ARCHIVE;
            }
            return RAZE_STATUS_IO;
        }

        nwritten = fwrite(buf, 1, nread, output);
        if (nwritten != nread) {
            return RAZE_STATUS_IO;
        }

        crc = raze_crc32_update(crc, buf, nread);
        remaining -= (uint64_t)nread;
    }

    if (crc32_present) {
        uint32_t actual = raze_crc32_final(crc);
        if (actual != expected_crc32) {
            return RAZE_STATUS_CRC_MISMATCH;
        }
    }

    return RAZE_STATUS_OK;
}

static RazeStatus decode_payload(
	FILE *archive,
	FILE *output,
	const RazeRar5FileHeader *fh
)
{
	if (archive == 0 || output == 0 || fh == 0) {
		return RAZE_STATUS_BAD_ARGUMENT;
	}

	if (fh->method == 0) {
		return copy_store_payload(
			archive,
			output,
			fh->pack_size,
			fh->crc32_present,
			fh->crc32
		);
	}

	return raze_extract_compressed_payload(archive, output, fh);
}

static RazeStatus handle_file_block(
    FILE *archive,
    const RazeRar5BlockHeader *block,
    const unsigned char *buf,
    size_t buf_len,
    const char *output_dir,
    const RazeExtractOptions *options,
    RazeOverwritePrompt *prompt,
    PendingDirMetaList *pending_dirs
) {
    RazeRar5FileHeader fh;
    struct stat st;
    char out_path[4096];
    FILE *output = 0;
    RazeStatus status;
    int remove_output = 0;

    memset(&fh, 0, sizeof(fh));

    if (!raze_rar5_parse_file_header(block, buf, buf_len, &fh)) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }

    status = ensure_supported_file(&fh);
    if (status != RAZE_STATUS_OK) {
        goto done;
    }

    status = raze_path_guard_join(output_dir, fh.name, fh.host_os, out_path, sizeof(out_path));
    if (status != RAZE_STATUS_OK) {
        goto done;
    }

    if (fh.is_dir) {
        mode_t dir_mode = 0;
        int has_mode = raze_fs_compute_mode(fh.host_os, fh.file_attr, 1, &dir_mode);
        int has_mtime = fh.mtime_present;
        time_t dir_mtime = (time_t)fh.unix_mtime;

        if (options != 0 && options->verbose && !options->quiet) {
            printf("mkdir %s\n", out_path);
        }

        status = raze_path_guard_make_dirs(out_path);
        if (status != RAZE_STATUS_OK) {
            goto done;
        }

        if (!skip_forward(archive, block->data_size)) {
            status = RAZE_STATUS_BAD_ARCHIVE;
            goto done;
        }

        status = pending_dir_meta_list_add(
            pending_dirs,
            out_path,
            has_mode,
            dir_mode,
            has_mtime,
            dir_mtime
        );
        goto done;
    }

    status = raze_path_guard_make_parent_dirs(out_path);
    if (status != RAZE_STATUS_OK) {
        goto done;
    }

    if (stat(out_path, &st) == 0) {
        RazeOverwriteStats overwrite_stats;
        RazeOverwriteDecision decision;

        if (S_ISDIR(st.st_mode)) {
            status = RAZE_STATUS_IO;
            goto done;
        }

        overwrite_stats.existing_size = (uint64_t)st.st_size;
        overwrite_stats.existing_mtime = st.st_mtime;
        overwrite_stats.existing_mtime_present = 1;
        overwrite_stats.archive_size = fh.unp_size;
        overwrite_stats.archive_mtime = (time_t)fh.unix_mtime;
        overwrite_stats.archive_mtime_present = fh.mtime_present;

        decision = raze_overwrite_prompt_decide(prompt, out_path, &overwrite_stats);
        if (decision == RAZE_OVERWRITE_DECISION_ABORT) {
            status = RAZE_STATUS_ABORTED;
            goto done;
        }
        if (decision == RAZE_OVERWRITE_DECISION_ERROR) {
            status = RAZE_STATUS_EXISTS;
            goto done;
        }
        if (decision == RAZE_OVERWRITE_DECISION_SKIP) {
            if (!skip_forward(archive, block->data_size)) {
                status = RAZE_STATUS_BAD_ARCHIVE;
                goto done;
            }
            if (options != 0 && options->verbose && !options->quiet) {
                printf("skip %s\n", out_path);
            }
            status = RAZE_STATUS_OK;
            goto done;
        }
    } else if (errno != ENOENT) {
        status = RAZE_STATUS_IO;
        goto done;
    }

    if (options != 0 && options->verbose && !options->quiet) {
        printf("extract %s\n", out_path);
    }

    output = fopen(out_path, "wb");
    if (output == 0) {
        status = RAZE_STATUS_IO;
        goto done;
    }

    status = decode_payload(archive, output, &fh);
    if (fclose(output) != 0 && status == RAZE_STATUS_OK) {
        status = RAZE_STATUS_IO;
    }
    output = 0;

    if (status == RAZE_STATUS_OK) {
        apply_entry_metadata(&fh, out_path, options != 0 ? options->quiet : 0);
    }

    if (status == RAZE_STATUS_CRC_MISMATCH || status == RAZE_STATUS_IO || status == RAZE_STATUS_BAD_ARCHIVE) {
        remove_output = 1;
    }

done:
    if (output != 0) {
        fclose(output);
    }
    if (remove_output) {
        remove(out_path);
    }
    raze_rar5_file_header_free(&fh);
    return status;
}

RazeStatus raze_extract_store_archive(
    const char *archive_path,
    const char *output_dir,
    const RazeExtractOptions *options
) {
    FILE *file;
    RazeOverwritePrompt prompt;
    PendingDirMetaList pending_dirs;
    RazeExtractOptions local_options;
    int saw_main = 0;
    int saw_end = 0;
    RazeStatus status;
    RazeRar5ReadResult rr;

    memset(&pending_dirs, 0, sizeof(pending_dirs));

    if (archive_path == 0 || output_dir == 0) {
        return RAZE_STATUS_BAD_ARGUMENT;
    }

    if (options == 0) {
        local_options = raze_extract_options_default();
        options = &local_options;
    }

    status = raze_path_guard_make_dirs(output_dir);
    if (status != RAZE_STATUS_OK) {
        return status;
    }

    file = fopen(archive_path, "rb");
    if (file == 0) {
        return RAZE_STATUS_IO;
    }

    status = raze_rar5_read_signature(file);
    if (status != RAZE_STATUS_OK) {
        fclose(file);
        return status;
    }

    raze_overwrite_prompt_init(&prompt, options->overwrite_mode);

    for (;;) {
        RazeRar5BlockHeader block;
        unsigned char *buf = 0;
        size_t buf_len = 0;

        rr = raze_rar5_read_block(file, &block, &buf, &buf_len, &status);
        if (rr == RAZE_RAR5_READ_EOF) {
            break;
        }
        if (rr == RAZE_RAR5_READ_ERROR) {
            free(buf);
            goto cleanup;
        }

        switch (block.header_type) {
            case RAZE_RAR5_HEAD_MAIN: {
                uint64_t arc_flags = 0;
                size_t consumed = 0;
                size_t cursor = block.body_offset;
                saw_main = 1;
                if (!raze_vint_decode(buf + cursor, block.extra_offset - cursor, &consumed, &arc_flags)) {
                    status = RAZE_STATUS_BAD_ARCHIVE;
                    free(buf);
                    goto cleanup;
                }
                if ((arc_flags & RAZE_RAR5_MHFL_VOLUME) != 0 ||
                    (arc_flags & RAZE_RAR5_MHFL_SOLID) != 0) {
                    status = RAZE_STATUS_UNSUPPORTED_FEATURE;
                    free(buf);
                    goto cleanup;
                }
                if (!skip_forward(file, block.data_size)) {
                    status = RAZE_STATUS_BAD_ARCHIVE;
                    free(buf);
                    goto cleanup;
                }
                break;
            }
            case RAZE_RAR5_HEAD_FILE:
                status = handle_file_block(
                    file,
                    &block,
                    buf,
                    buf_len,
                    output_dir,
                    options,
                    &prompt,
                    &pending_dirs
                );
                if (status != RAZE_STATUS_OK) {
                    free(buf);
                    goto cleanup;
                }
                break;
            case RAZE_RAR5_HEAD_SERVICE: {
                RazeRar5FileHeader service_header;
                memset(&service_header, 0, sizeof(service_header));
                if (!raze_rar5_parse_file_header(&block, buf, buf_len, &service_header)) {
                    status = RAZE_STATUS_BAD_ARCHIVE;
                    free(buf);
                    goto cleanup;
                }
                if (service_header.encrypted) {
                    status = RAZE_STATUS_UNSUPPORTED_FEATURE;
                    raze_rar5_file_header_free(&service_header);
                    free(buf);
                    goto cleanup;
                }
                if (!skip_forward(file, block.data_size)) {
                    status = RAZE_STATUS_BAD_ARCHIVE;
                    raze_rar5_file_header_free(&service_header);
                    free(buf);
                    goto cleanup;
                }
                raze_rar5_file_header_free(&service_header);
                break;
            }
            case RAZE_RAR5_HEAD_CRYPT:
                status = RAZE_STATUS_UNSUPPORTED_FEATURE;
                free(buf);
                goto cleanup;
            case RAZE_RAR5_HEAD_ENDARC:
                saw_end = 1;
                if (!skip_forward(file, block.data_size)) {
                    status = RAZE_STATUS_BAD_ARCHIVE;
                    free(buf);
                    goto cleanup;
                }
                break;
            default:
                if (!skip_forward(file, block.data_size)) {
                    status = RAZE_STATUS_BAD_ARCHIVE;
                    free(buf);
                    goto cleanup;
                }
                break;
        }

        free(buf);
    }

    if (!saw_main || !saw_end) {
        status = RAZE_STATUS_BAD_ARCHIVE;
        goto cleanup;
    }

    apply_pending_dir_metadata(&pending_dirs, options->quiet);
    status = RAZE_STATUS_OK;

cleanup:
    pending_dir_meta_list_free(&pending_dirs);
    fclose(file);
    return status;
}
