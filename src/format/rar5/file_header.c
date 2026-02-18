#include "file_header.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "vint.h"

#define RAZE_RAR5_HFL_SPLITBEFORE 0x0008U
#define RAZE_RAR5_HFL_SPLITAFTER 0x0010U
#define RAZE_RAR5_FCI_SOLID 0x00000040U
#define RAZE_RAR5_FHEXTRA_CRYPT 0x01U

static uint32_t read_u32le(const unsigned char raw[4]) {
    return ((uint32_t)raw[0]) |
           ((uint32_t)raw[1] << 8) |
           ((uint32_t)raw[2] << 16) |
           ((uint32_t)raw[3] << 24);
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

int raze_rar5_parse_file_header(
    const RazeRar5BlockHeader *block,
    const unsigned char *buf,
    size_t buf_len,
    RazeRar5FileHeader *file_header
) {
    size_t cursor;
    size_t consumed = 0;
    uint64_t comp_info = 0;
    uint64_t name_len = 0;
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

    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &file_header->file_attr)) {
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
        raze_rar5_file_header_free(file_header);
        return 0;
    }

    return 1;
}

void raze_rar5_file_header_free(RazeRar5FileHeader *file_header) {
    if (file_header == 0) {
        return;
    }
    free(file_header->name);
    file_header->name = 0;
    file_header->name_len = 0;
}
