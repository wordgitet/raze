#include "extract_store.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "../checksum/crc32.h"
#include "../cli/overwrite_prompt.h"
#include "../format/rar5/block_reader.h"
#include "../format/rar5/vint.h"
#include "../io/path_guard.h"
#include "decode_internal.h"

#define RAZE_RAR5_HEAD_MAIN 1U
#define RAZE_RAR5_HEAD_FILE 2U
#define RAZE_RAR5_HEAD_SERVICE 3U
#define RAZE_RAR5_HEAD_CRYPT 4U
#define RAZE_RAR5_HEAD_ENDARC 5U

#define RAZE_RAR5_HFL_SPLITBEFORE 0x0008U
#define RAZE_RAR5_HFL_SPLITAFTER 0x0010U

#define RAZE_RAR5_MHFL_VOLUME 0x0001U
#define RAZE_RAR5_MHFL_SOLID 0x0004U

#define RAZE_RAR5_FHFL_DIRECTORY 0x0001U
#define RAZE_RAR5_FHFL_UTIME 0x0002U
#define RAZE_RAR5_FHFL_CRC32 0x0004U
#define RAZE_RAR5_FHFL_UNPUNKNOWN 0x0008U

#define RAZE_RAR5_FCI_SOLID 0x00000040U
#define RAZE_RAR5_FHEXTRA_CRYPT 0x01U
#define RAZE_RAR5_HOST_OS_WINDOWS 0U
#define RAZE_RAR5_HOST_OS_UNIX 1U

static uint32_t read_u32le(const unsigned char raw[4]) {
    return ((uint32_t)raw[0]) |
           ((uint32_t)raw[1] << 8) |
           ((uint32_t)raw[2] << 16) |
           ((uint32_t)raw[3] << 24);
}

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

static int parse_extra_has_crypt(const unsigned char *buf, size_t extra_len) {
    size_t cursor = 0;

    while (cursor < extra_len) {
        uint64_t field_size = 0;
        uint64_t field_type = 0;
        size_t consumed = 0;
        size_t next_pos;

        if (!raze_vint_decode(buf + cursor, extra_len - cursor, &consumed, &field_size)) {
            return 0;
        }
        cursor += consumed;
        if (field_size == 0 || field_size > extra_len - cursor) {
            return 0;
        }

        next_pos = cursor + (size_t)field_size;
        if (!raze_vint_decode(buf + cursor, next_pos - cursor, &consumed, &field_type)) {
            return 0;
        }
        cursor += consumed;

        if (field_type == RAZE_RAR5_FHEXTRA_CRYPT) {
            return 1;
        }
        cursor = next_pos;
    }

    return 0;
}

static int parse_file_header(
    const RazeRar5BlockHeader *block,
    const unsigned char *buf,
    size_t buf_len,
    RazeRar5FileHeader *file_header
) {
    size_t cursor;
    size_t consumed = 0;
    uint64_t comp_info = 0;
    uint64_t name_len = 0;
    uint64_t dummy = 0;
    unsigned char crc_raw[4];

    if (block == 0 || buf == 0 || file_header == 0) {
        return 0;
    }
    if (block->extra_offset > buf_len || block->body_offset > block->extra_offset) {
        return 0;
    }

    memset(file_header, 0, sizeof(*file_header));
    file_header->pack_size = block->data_size;
    file_header->split_before = (block->flags & RAZE_RAR5_HFL_SPLITBEFORE) != 0;
    file_header->split_after = (block->flags & RAZE_RAR5_HFL_SPLITAFTER) != 0;
    cursor = block->body_offset;

    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &file_header->file_flags)) {
        return 0;
    }
    cursor += consumed;

    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &file_header->unp_size)) {
        return 0;
    }
    cursor += consumed;

    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &dummy)) {
        return 0;
    }
    cursor += consumed;

    if ((file_header->file_flags & RAZE_RAR5_FHFL_UTIME) != 0) {
        if (block->extra_offset - cursor < 4) {
            return 0;
        }
        file_header->unix_mtime = read_u32le(buf + cursor);
        file_header->mtime_present = 1;
        cursor += 4;
    }

    if ((file_header->file_flags & RAZE_RAR5_FHFL_CRC32) != 0) {
        if (block->extra_offset - cursor < 4) {
            return 0;
        }
        memcpy(crc_raw, buf + cursor, sizeof(crc_raw));
        file_header->crc32 = read_u32le(crc_raw);
        file_header->crc32_present = 1;
        cursor += 4;
    }

    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &comp_info)) {
        return 0;
    }
    cursor += consumed;

    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &file_header->host_os)) {
        return 0;
    }
    cursor += consumed;

    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &name_len)) {
        return 0;
    }
    cursor += consumed;

    if (name_len == 0 || name_len > block->extra_offset - cursor || name_len >= (uint64_t)SIZE_MAX) {
        return 0;
    }
    if (memchr(buf + cursor, '\0', (size_t)name_len) != 0) {
        return 0;
    }

    file_header->name = (char *)malloc((size_t)name_len + 1U);
    if (file_header->name == 0) {
        return 0;
    }
    memcpy(file_header->name, buf + cursor, (size_t)name_len);
    file_header->name[(size_t)name_len] = '\0';
    file_header->name_len = (size_t)name_len;
    cursor += (size_t)name_len;

    file_header->method = (comp_info >> 7U) & 0x7U;
    file_header->solid = (comp_info & RAZE_RAR5_FCI_SOLID) != 0;
    file_header->is_dir = (file_header->file_flags & RAZE_RAR5_FHFL_DIRECTORY) != 0;

    if (block->extra_size > 0) {
        const unsigned char *extra_ptr = buf + block->extra_offset;
        if (parse_extra_has_crypt(extra_ptr, (size_t)block->extra_size)) {
            file_header->encrypted = 1;
        }
    }

    if (cursor > buf_len) {
        free(file_header->name);
        file_header->name = 0;
        file_header->name_len = 0;
        return 0;
    }

    return 1;
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
    if (fh->method != 0) {
        return RAZE_STATUS_UNSUPPORTED_FEATURE;
    }
    if (fh->host_os != RAZE_RAR5_HOST_OS_WINDOWS &&
        fh->host_os != RAZE_RAR5_HOST_OS_UNIX) {
        return RAZE_STATUS_UNSUPPORTED_FEATURE;
    }
    if (!fh->is_dir && fh->pack_size != fh->unp_size) {
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

static RazeStatus handle_file_block(
    FILE *archive,
    const RazeRar5BlockHeader *block,
    const unsigned char *buf,
    size_t buf_len,
    const char *output_dir,
    const RazeExtractOptions *options,
    RazeOverwritePrompt *prompt
) {
    RazeRar5FileHeader fh;
    struct stat st;
    char out_path[4096];
    FILE *output = 0;
    RazeStatus status;
    int remove_output = 0;

    memset(&fh, 0, sizeof(fh));

    if (!parse_file_header(block, buf, buf_len, &fh)) {
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
        status = RAZE_STATUS_OK;
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

    status = copy_store_payload(archive, output, fh.pack_size, fh.crc32_present, fh.crc32);
    if (fclose(output) != 0 && status == RAZE_STATUS_OK) {
        status = RAZE_STATUS_IO;
    }
    output = 0;

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
    free(fh.name);
    return status;
}

RazeStatus raze_extract_store_archive(
    const char *archive_path,
    const char *output_dir,
    const RazeExtractOptions *options
) {
    FILE *file;
    RazeOverwritePrompt prompt;
    RazeExtractOptions local_options;
    int saw_main = 0;
    int saw_end = 0;
    RazeStatus status;
    RazeRar5ReadResult rr;

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
            fclose(file);
            return status;
        }

        switch (block.header_type) {
            case RAZE_RAR5_HEAD_MAIN: {
                uint64_t arc_flags = 0;
                size_t consumed = 0;
                size_t cursor = block.body_offset;
                saw_main = 1;
                if (!raze_vint_decode(buf + cursor, block.extra_offset - cursor, &consumed, &arc_flags)) {
                    free(buf);
                    fclose(file);
                    return RAZE_STATUS_BAD_ARCHIVE;
                }
                if ((arc_flags & RAZE_RAR5_MHFL_VOLUME) != 0 ||
                    (arc_flags & RAZE_RAR5_MHFL_SOLID) != 0) {
                    free(buf);
                    fclose(file);
                    return RAZE_STATUS_UNSUPPORTED_FEATURE;
                }
                if (!skip_forward(file, block.data_size)) {
                    free(buf);
                    fclose(file);
                    return RAZE_STATUS_BAD_ARCHIVE;
                }
                break;
            }
            case RAZE_RAR5_HEAD_FILE:
                status = handle_file_block(file, &block, buf, buf_len, output_dir, options, &prompt);
                if (status != RAZE_STATUS_OK) {
                    free(buf);
                    fclose(file);
                    return status;
                }
                break;
            case RAZE_RAR5_HEAD_SERVICE: {
                RazeRar5FileHeader service_header;
                memset(&service_header, 0, sizeof(service_header));
                if (!parse_file_header(&block, buf, buf_len, &service_header)) {
                    free(buf);
                    fclose(file);
                    return RAZE_STATUS_BAD_ARCHIVE;
                }
                if (service_header.encrypted) {
                    free(service_header.name);
                    free(buf);
                    fclose(file);
                    return RAZE_STATUS_UNSUPPORTED_FEATURE;
                }
                if (!skip_forward(file, block.data_size)) {
                    free(service_header.name);
                    free(buf);
                    fclose(file);
                    return RAZE_STATUS_BAD_ARCHIVE;
                }
                free(service_header.name);
                break;
            }
            case RAZE_RAR5_HEAD_CRYPT:
                free(buf);
                fclose(file);
                return RAZE_STATUS_UNSUPPORTED_FEATURE;
            case RAZE_RAR5_HEAD_ENDARC:
                saw_end = 1;
                if (!skip_forward(file, block.data_size)) {
                    free(buf);
                    fclose(file);
                    return RAZE_STATUS_BAD_ARCHIVE;
                }
                break;
            default:
                if (!skip_forward(file, block.data_size)) {
                    free(buf);
                    fclose(file);
                    return RAZE_STATUS_BAD_ARCHIVE;
                }
                break;
        }

        free(buf);
    }

    fclose(file);
    if (!saw_main || !saw_end) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }
    return RAZE_STATUS_OK;
}
