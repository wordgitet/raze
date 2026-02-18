#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../decode/decode_internal.h"
#include "block_reader.h"
#include "file_header.h"
#include "vint.h"

#define RAZE_RAR5_HEAD_MAIN 1U
#define RAZE_RAR5_HEAD_FILE 2U
#define RAZE_RAR5_HEAD_SERVICE 3U
#define RAZE_RAR5_HEAD_CRYPT 4U
#define RAZE_RAR5_HEAD_ENDARC 5U

#define RAZE_RAR5_MHFL_VOLUME 0x0001U
#define RAZE_RAR5_MHFL_SOLID 0x0004U

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
            case RAZE_RAR5_HEAD_SERVICE: {
                RazeRar5FileHeader fh;

                if (!raze_rar5_parse_file_header(&block, buf, buf_len, &fh)) {
                    free(buf);
                    fclose(file);
                    return RAZE_STATUS_BAD_ARCHIVE;
                }

                if (fh.split_before || fh.split_after) {
                    scan->has_split = 1;
                }
                if ((fh.file_flags & RAZE_RAR5_FHFL_UNPUNKNOWN) != 0) {
                    scan->has_unknown_unp_size = 1;
                }
                if (fh.solid) {
                    scan->has_solid = 1;
                }
                if (fh.method != 0) {
                    scan->has_compressed_method = 1;
                } else {
                    scan->store_file_count += 1;
                }
                if (fh.encrypted) {
                    scan->has_encryption = 1;
                }

                if (block.header_type == RAZE_RAR5_HEAD_FILE && !fh.is_dir) {
                    scan->file_count += 1;
                }

                raze_rar5_file_header_free(&fh);
                break;
            }
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
        scan->has_split || scan->has_unknown_unp_size) {
        return RAZE_STATUS_UNSUPPORTED_FEATURE;
    }

    return RAZE_STATUS_OK;
}
