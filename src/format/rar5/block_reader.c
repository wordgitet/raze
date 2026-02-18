#include "block_reader.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "../../checksum/crc32.h"
#include "vint.h"

#define RAZE_RAR5_MAX_HEADER_SIZE (2U * 1024U * 1024U)
#define RAZE_RAR5_MAX_SFX_SIZE (1024U * 1024U)
#define RAZE_RAR5_HEADER_SIZE_MAX_BYTES 3U
#define RAZE_RAR5_HFL_EXTRA 0x0001U
#define RAZE_RAR5_HFL_DATA 0x0002U

static int read_exact(FILE *file, unsigned char *buf, size_t len) {
    size_t nread;

    if (len == 0) {
        return 1;
    }

    nread = fread(buf, 1, len, file);
    return nread == len;
}

static uint32_t read_u32le(const unsigned char raw[4]) {
    return ((uint32_t)raw[0]) |
           ((uint32_t)raw[1] << 8) |
           ((uint32_t)raw[2] << 16) |
           ((uint32_t)raw[3] << 24);
}

static int current_file_offset(FILE *file, uint64_t *offset) {
    long pos;

    if (file == 0 || offset == 0) {
        return 0;
    }

    pos = ftell(file);
    if (pos < 0) {
        return 0;
    }

    *offset = (uint64_t)(unsigned long)pos;
    return 1;
}

RazeStatus raze_rar5_read_signature(FILE *file) {
    unsigned char *sig_window = 0;
    static const unsigned char expected[8] = {
        0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00
    };
    size_t window_len = RAZE_RAR5_MAX_SFX_SIZE + sizeof(expected);
    size_t nread;
    size_t i;

    if (file == 0) {
        return RAZE_STATUS_BAD_ARGUMENT;
    }

    if (fseek(file, 0, SEEK_SET) != 0) {
        return RAZE_STATUS_IO;
    }

    sig_window = (unsigned char *)malloc(window_len);
    if (sig_window == 0) {
        return RAZE_STATUS_IO;
    }

    nread = fread(sig_window, 1, window_len, file);
    if (ferror(file)) {
        free(sig_window);
        return RAZE_STATUS_IO;
    }

    for (i = 0; i + sizeof(expected) <= nread; ++i) {
        if (memcmp(sig_window + i, expected, sizeof(expected)) == 0) {
            if (fseek(file, (long)(i + sizeof(expected)), SEEK_SET) != 0) {
                free(sig_window);
                return RAZE_STATUS_IO;
            }
            free(sig_window);
            return RAZE_STATUS_OK;
        }
    }

    free(sig_window);
    return RAZE_STATUS_UNSUPPORTED;
}

RazeRar5ReadResult raze_rar5_read_block(
    FILE *file,
    RazeRar5BlockHeader *block,
    unsigned char **header_buf,
    size_t *header_buf_len,
    RazeStatus *error_status
) {
    unsigned char crc_raw[4];
    unsigned char size_raw[RAZE_RAR5_HEADER_SIZE_MAX_BYTES];
    size_t size_raw_len = 0;
    uint64_t header_size_u64 = 0;
    uint64_t header_type = 0;
    uint64_t flags = 0;
    uint64_t extra_size = 0;
    uint64_t data_size = 0;
    size_t consumed = 0;
    size_t cursor = 0;
    unsigned char *buf = 0;
    uint32_t crc_calc;
    uint32_t crc_init;
    uint64_t header_offset = 0;

    if (error_status != 0) {
        *error_status = RAZE_STATUS_ERROR;
    }

    if (file == 0 || block == 0 || header_buf == 0 || header_buf_len == 0 || error_status == 0) {
        if (error_status != 0) {
            *error_status = RAZE_STATUS_BAD_ARGUMENT;
        }
        return RAZE_RAR5_READ_ERROR;
    }

    *header_buf = 0;
    *header_buf_len = 0;
    memset(block, 0, sizeof(*block));

    if (!current_file_offset(file, &header_offset)) {
        *error_status = RAZE_STATUS_IO;
        return RAZE_RAR5_READ_ERROR;
    }
    if (feof(file)) {
        return RAZE_RAR5_READ_EOF;
    }

    if (!read_exact(file, crc_raw, sizeof(crc_raw))) {
        if (feof(file)) {
            return RAZE_RAR5_READ_EOF;
        }
        *error_status = RAZE_STATUS_IO;
        return RAZE_RAR5_READ_ERROR;
    }

    while (size_raw_len < sizeof(size_raw)) {
        int ch = fgetc(file);
        if (ch == EOF) {
            *error_status = RAZE_STATUS_BAD_ARCHIVE;
            return RAZE_RAR5_READ_ERROR;
        }
        size_raw[size_raw_len++] = (unsigned char)ch;
        if ((size_raw[size_raw_len - 1] & 0x80U) == 0) {
            break;
        }
    }

    if (size_raw_len == sizeof(size_raw) && (size_raw[size_raw_len - 1] & 0x80U) != 0) {
        *error_status = RAZE_STATUS_BAD_ARCHIVE;
        return RAZE_RAR5_READ_ERROR;
    }

    if (!raze_vint_decode(size_raw, size_raw_len, &consumed, &header_size_u64)) {
        *error_status = RAZE_STATUS_BAD_ARCHIVE;
        return RAZE_RAR5_READ_ERROR;
    }

    if (consumed != size_raw_len || header_size_u64 == 0 || header_size_u64 > RAZE_RAR5_MAX_HEADER_SIZE) {
        *error_status = RAZE_STATUS_BAD_ARCHIVE;
        return RAZE_RAR5_READ_ERROR;
    }

    buf = (unsigned char *)malloc((size_t)header_size_u64);
    if (buf == 0) {
        *error_status = RAZE_STATUS_IO;
        return RAZE_RAR5_READ_ERROR;
    }

    if (!read_exact(file, buf, (size_t)header_size_u64)) {
        free(buf);
        *error_status = RAZE_STATUS_BAD_ARCHIVE;
        return RAZE_RAR5_READ_ERROR;
    }

    if (!raze_vint_decode(buf + cursor, (size_t)header_size_u64 - cursor, &consumed, &header_type)) {
        free(buf);
        *error_status = RAZE_STATUS_BAD_ARCHIVE;
        return RAZE_RAR5_READ_ERROR;
    }
    cursor += consumed;

    if (!raze_vint_decode(buf + cursor, (size_t)header_size_u64 - cursor, &consumed, &flags)) {
        free(buf);
        *error_status = RAZE_STATUS_BAD_ARCHIVE;
        return RAZE_RAR5_READ_ERROR;
    }
    cursor += consumed;

    if ((flags & RAZE_RAR5_HFL_EXTRA) != 0) {
        if (!raze_vint_decode(buf + cursor, (size_t)header_size_u64 - cursor, &consumed, &extra_size)) {
            free(buf);
            *error_status = RAZE_STATUS_BAD_ARCHIVE;
            return RAZE_RAR5_READ_ERROR;
        }
        cursor += consumed;
        if (extra_size > header_size_u64) {
            free(buf);
            *error_status = RAZE_STATUS_BAD_ARCHIVE;
            return RAZE_RAR5_READ_ERROR;
        }
    }

    if ((flags & RAZE_RAR5_HFL_DATA) != 0) {
        if (!raze_vint_decode(buf + cursor, (size_t)header_size_u64 - cursor, &consumed, &data_size)) {
            free(buf);
            *error_status = RAZE_STATUS_BAD_ARCHIVE;
            return RAZE_RAR5_READ_ERROR;
        }
        cursor += consumed;
    }

    crc_init = raze_crc32_init();
    crc_init = raze_crc32_update(crc_init, size_raw, size_raw_len);
    crc_init = raze_crc32_update(crc_init, buf, (size_t)header_size_u64);
    crc_calc = raze_crc32_final(crc_init);

    block->header_offset = header_offset;
    block->data_offset = header_offset + 4U + (uint64_t)size_raw_len + header_size_u64;
    block->next_offset = block->data_offset + data_size;
    block->header_type = header_type;
    block->flags = flags;
    block->header_size = header_size_u64;
    block->data_size = data_size;
    block->extra_size = extra_size;
    block->header_crc = read_u32le(crc_raw);
    block->crc_ok = block->header_crc == crc_calc;
    block->body_offset = cursor;
    block->extra_offset = (size_t)(header_size_u64 - extra_size);

    *header_buf = buf;
    *header_buf_len = (size_t)header_size_u64;
    *error_status = block->crc_ok ? RAZE_STATUS_OK : RAZE_STATUS_BAD_ARCHIVE;

    if (!block->crc_ok) {
        return RAZE_RAR5_READ_ERROR;
    }

    return RAZE_RAR5_READ_OK;
}
