#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../decode/decode_internal.h"
#include "block_reader.h"
#include "vint.h"

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

static int parse_file_like_header(
    const RazeRar5BlockHeader *block,
    const unsigned char *buf,
    size_t buf_len,
    RazeRar5Scan *scan
) {
    size_t cursor = block->body_offset;
    size_t consumed = 0;
    uint64_t file_flags = 0;
    uint64_t comp_info = 0;
    uint64_t name_len = 0;
    uint64_t file_method = 0;
    uint64_t dummy = 0;

    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &file_flags)) {
        return 0;
    }
    cursor += consumed;

    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &dummy)) {
        return 0;
    }
    cursor += consumed;

    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &dummy)) {
        return 0;
    }
    cursor += consumed;

    if ((file_flags & RAZE_RAR5_FHFL_UTIME) != 0) {
        if (block->extra_offset - cursor < 4) {
            return 0;
        }
        cursor += 4;
    }

    if ((file_flags & RAZE_RAR5_FHFL_CRC32) != 0) {
        if (block->extra_offset - cursor < 4) {
            return 0;
        }
        cursor += 4;
    }

    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &comp_info)) {
        return 0;
    }
    cursor += consumed;

    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &dummy)) {
        return 0;
    }
    cursor += consumed;

    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &name_len)) {
        return 0;
    }
    cursor += consumed;

    if (name_len > block->extra_offset - cursor) {
        return 0;
    }
    cursor += (size_t)name_len;

    file_method = (comp_info >> 7U) & 0x7U;

    if ((block->flags & (RAZE_RAR5_HFL_SPLITBEFORE | RAZE_RAR5_HFL_SPLITAFTER)) != 0) {
        scan->has_split = 1;
    }
    if ((file_flags & RAZE_RAR5_FHFL_UNPUNKNOWN) != 0) {
        scan->has_unknown_unp_size = 1;
    }
    if ((comp_info & RAZE_RAR5_FCI_SOLID) != 0) {
        scan->has_solid = 1;
    }
    if (file_method != 0) {
        scan->has_compressed_method = 1;
    } else {
        scan->store_file_count += 1;
    }

    if (block->header_type == RAZE_RAR5_HEAD_FILE &&
        (file_flags & RAZE_RAR5_FHFL_DIRECTORY) == 0) {
        scan->file_count += 1;
    }

    if (block->extra_size > 0) {
        const unsigned char *extra_ptr = buf + block->extra_offset;
        if (parse_extra_has_crypt(extra_ptr, (size_t)block->extra_size)) {
            scan->has_encryption = 1;
        }
    }

    if (cursor > buf_len) {
        return 0;
    }
    return 1;
}

int rar5_parser_probe(const char *archive_path) {
    FILE *file;
    RazeStatus status;

    if (archive_path == 0) {
        return 0;
    }

    file = fopen(archive_path, "rb");
    if (file == 0) {
        return 0;
    }

    status = raze_rar5_read_signature(file);
    fclose(file);
    return status == RAZE_STATUS_OK;
}

RazeStatus rar5_scan_archive(const char *archive_path, RazeRar5Scan *scan) {
    FILE *file;
    RazeStatus status;
    RazeRar5ReadResult rr;

    if (archive_path == 0 || scan == 0) {
        return RAZE_STATUS_BAD_ARGUMENT;
    }

    memset(scan, 0, sizeof(*scan));

    file = fopen(archive_path, "rb");
    if (file == 0) {
        return RAZE_STATUS_IO;
    }

    status = raze_rar5_read_signature(file);
    if (status != RAZE_STATUS_OK) {
        fclose(file);
        return status;
    }
    scan->is_rar5 = 1;

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
                scan->saw_main_header = 1;
                if (!raze_vint_decode(buf + cursor, block.extra_offset - cursor, &consumed, &arc_flags)) {
                    free(buf);
                    fclose(file);
                    return RAZE_STATUS_BAD_ARCHIVE;
                }
                if ((arc_flags & RAZE_RAR5_MHFL_VOLUME) != 0) {
                    scan->has_multivolume = 1;
                }
                if ((arc_flags & RAZE_RAR5_MHFL_SOLID) != 0) {
                    scan->has_solid = 1;
                }
                break;
            }
            case RAZE_RAR5_HEAD_FILE:
            case RAZE_RAR5_HEAD_SERVICE:
                if (!parse_file_like_header(&block, buf, buf_len, scan)) {
                    free(buf);
                    fclose(file);
                    return RAZE_STATUS_BAD_ARCHIVE;
                }
                break;
            case RAZE_RAR5_HEAD_CRYPT:
                scan->has_encryption = 1;
                break;
            case RAZE_RAR5_HEAD_ENDARC:
                scan->saw_end_archive = 1;
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

    if (!scan->saw_main_header || !scan->saw_end_archive) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }

    if (scan->has_encryption || scan->has_multivolume || scan->has_solid ||
        scan->has_split || scan->has_compressed_method || scan->has_unknown_unp_size) {
        return RAZE_STATUS_UNSUPPORTED_FEATURE;
    }

    return RAZE_STATUS_OK;
}
