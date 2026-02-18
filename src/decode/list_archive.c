#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../format/rar5/block_reader.h"
#include "../format/rar5/vint.h"
#include "decode_internal.h"

#define RAZE_RAR5_HEAD_MAIN 1U
#define RAZE_RAR5_HEAD_FILE 2U
#define RAZE_RAR5_HEAD_SERVICE 3U
#define RAZE_RAR5_HEAD_CRYPT 4U
#define RAZE_RAR5_HEAD_ENDARC 5U

#define RAZE_RAR5_HFL_SPLITBEFORE 0x0008U
#define RAZE_RAR5_HFL_SPLITAFTER 0x0010U

#define RAZE_RAR5_FHFL_DIRECTORY 0x0001U
#define RAZE_RAR5_FHFL_UTIME 0x0002U
#define RAZE_RAR5_FHFL_CRC32 0x0004U

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

static int parse_file_like_header(
    const RazeRar5BlockHeader *block,
    const unsigned char *buf,
    size_t buf_len,
    RazeRar5FileHeader *out
) {
    size_t cursor = block->body_offset;
    size_t consumed = 0;
    uint64_t comp_info = 0;
    uint64_t name_len = 0;
    uint64_t attrs = 0;

    if (block == 0 || buf == 0 || out == 0) {
        return 0;
    }
    if (block->extra_offset > buf_len || block->body_offset > block->extra_offset) {
        return 0;
    }

    memset(out, 0, sizeof(*out));
    out->pack_size = block->data_size;
    out->split_before = (block->flags & RAZE_RAR5_HFL_SPLITBEFORE) != 0;
    out->split_after = (block->flags & RAZE_RAR5_HFL_SPLITAFTER) != 0;

    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &out->file_flags)) {
        return 0;
    }
    cursor += consumed;

    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &out->unp_size)) {
        return 0;
    }
    cursor += consumed;

    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &attrs)) {
        return 0;
    }
    cursor += consumed;
    (void)attrs;

    if ((out->file_flags & RAZE_RAR5_FHFL_UTIME) != 0) {
        if (block->extra_offset - cursor < 4) {
            return 0;
        }
        out->mtime_present = 1;
        cursor += 4;
    }

    if ((out->file_flags & RAZE_RAR5_FHFL_CRC32) != 0) {
        if (block->extra_offset - cursor < 4) {
            return 0;
        }
        out->crc32_present = 1;
        cursor += 4;
    }

    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &comp_info)) {
        return 0;
    }
    cursor += consumed;

    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &out->host_os)) {
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

    out->name = (char *)malloc((size_t)name_len + 1U);
    if (out->name == 0) {
        return 0;
    }
    memcpy(out->name, buf + cursor, (size_t)name_len);
    out->name[(size_t)name_len] = '\0';
    out->name_len = (size_t)name_len;

    out->method = (comp_info >> 7U) & 0x7U;
    out->is_dir = (out->file_flags & RAZE_RAR5_FHFL_DIRECTORY) != 0;

    return 1;
}

static void print_entry(
    const RazeRar5FileHeader *fh,
    int technical,
    int is_service
) {
    if (fh == 0 || fh->name == 0) {
        return;
    }

    if (!technical) {
        if (!is_service) {
            printf("%10llu %s%s\n",
                (unsigned long long)fh->unp_size,
                fh->name,
                fh->is_dir ? "/" : "");
        }
        return;
    }

    printf(
        "type=%s name=%s%s method=%llu pack=%llu unp=%llu host_os=%llu split_before=%d split_after=%d\n",
        is_service ? "service" : "file",
        fh->name,
        fh->is_dir ? "/" : "",
        (unsigned long long)fh->method,
        (unsigned long long)fh->pack_size,
        (unsigned long long)fh->unp_size,
        (unsigned long long)fh->host_os,
        fh->split_before,
        fh->split_after
    );
}

RazeStatus raze_list_rar5_archive(const char *archive_path, int technical) {
    FILE *file;
    RazeStatus status;
    RazeRar5ReadResult rr;
    int saw_main = 0;
    int saw_end = 0;

    if (archive_path == 0) {
        return RAZE_STATUS_BAD_ARGUMENT;
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
            case RAZE_RAR5_HEAD_MAIN:
                saw_main = 1;
                break;
            case RAZE_RAR5_HEAD_FILE:
            case RAZE_RAR5_HEAD_SERVICE: {
                RazeRar5FileHeader fh;
                memset(&fh, 0, sizeof(fh));
                if (!parse_file_like_header(&block, buf, buf_len, &fh)) {
                    free(buf);
                    fclose(file);
                    return RAZE_STATUS_BAD_ARCHIVE;
                }
                print_entry(&fh, technical, block.header_type == RAZE_RAR5_HEAD_SERVICE);
                free(fh.name);
                break;
            }
            case RAZE_RAR5_HEAD_CRYPT:
                free(buf);
                fclose(file);
                return RAZE_STATUS_UNSUPPORTED_FEATURE;
            case RAZE_RAR5_HEAD_ENDARC:
                saw_end = 1;
                break;
            default:
                break;
        }

        free(buf);

        if (!skip_forward(file, block.data_size)) {
            fclose(file);
            return RAZE_STATUS_BAD_ARCHIVE;
        }
    }

    fclose(file);

    if (!saw_main || !saw_end) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }

    return RAZE_STATUS_OK;
}
