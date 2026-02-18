#include "file_header.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "vint.h"

#define RAZE_RAR5_HFL_SPLITBEFORE 0x0008U
#define RAZE_RAR5_HFL_SPLITAFTER 0x0010U
#define RAZE_RAR5_FCI_SOLID 0x00000040U
#define RAZE_RAR5_FCI_VERSION_MASK 0x0000003fU
#define RAZE_RAR5_FCI_METHOD_MASK 0x00000380U
#define RAZE_RAR5_FCI_DICT_BASE_MASK 0x00007c00U
#define RAZE_RAR5_FCI_DICT_EXTRA_MASK 0x000f8000U
#define RAZE_RAR5_FCI_V50_COMPAT 0x00100000U
#define RAZE_RAR5_FHEXTRA_CRYPT 0x01U
#define RAZE_RAR5_FHEXTRA_HASH 0x02U
#define RAZE_RAR5_FHEXTRA_CRYPT_PSWCHECK 0x01U
#define RAZE_RAR5_FHEXTRA_CRYPT_HASHMAC 0x02U
#define RAZE_RAR5_FHEXTRA_HASH_BLAKE2SP 0x00U
#define RAZE_RAR5_CRYPT_KDF_LG2_MAX 24U
#define RAZE_RAR5_DICT_BASE_BYTES (128U * 1024U)
#define RAZE_RAR5_BLAKE2SP_DIGEST_SIZE 32U

static uint32_t read_u32le(const unsigned char raw[4]) {
    return ((uint32_t)raw[0]) |
           ((uint32_t)raw[1] << 8) |
           ((uint32_t)raw[2] << 16) |
           ((uint32_t)raw[3] << 24);
}

static RazeStatus parse_crypt_extra(
    const unsigned char *buf,
    size_t len,
    RazeRar5FileHeader *file_header
) {
    size_t cursor = 0;
    size_t consumed = 0;
    uint64_t enc_version = 0;
    uint64_t enc_flags = 0;

    if (buf == 0 || file_header == 0) {
        return RAZE_STATUS_BAD_ARGUMENT;
    }

    if (!raze_vint_decode(buf + cursor, len - cursor, &consumed, &enc_version)) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }
    cursor += consumed;
    if (!raze_vint_decode(buf + cursor, len - cursor, &consumed, &enc_flags)) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }
    cursor += consumed;

    if (cursor + 1U + 16U + 16U > len) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }

    file_header->crypt_version = (uint8_t)enc_version;
    file_header->crypt_use_psw_check = (enc_flags & RAZE_RAR5_FHEXTRA_CRYPT_PSWCHECK) != 0U;
    file_header->crypt_use_hash_key = (enc_flags & RAZE_RAR5_FHEXTRA_CRYPT_HASHMAC) != 0U;
    file_header->crypt_lg2_count = buf[cursor++];
    if (file_header->crypt_lg2_count > RAZE_RAR5_CRYPT_KDF_LG2_MAX) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }

    memcpy(file_header->crypt_salt, buf + cursor, 16U);
    cursor += 16U;
    memcpy(file_header->crypt_initv, buf + cursor, 16U);
    cursor += 16U;

    if (file_header->crypt_use_psw_check) {
        if (cursor + 8U + 4U > len) {
            return RAZE_STATUS_BAD_ARCHIVE;
        }
        memcpy(file_header->crypt_psw_check, buf + cursor, 8U);
        cursor += 8U;
        memcpy(file_header->crypt_psw_check_csum, buf + cursor, 4U);
        cursor += 4U;
    }

    return RAZE_STATUS_OK;
}

static RazeStatus parse_hash_extra(
    const unsigned char *buf,
    size_t len,
    RazeRar5FileHeader *file_header
) {
    uint64_t hash_type = 0;
    size_t consumed = 0;

    if (buf == 0 || file_header == 0) {
        return RAZE_STATUS_BAD_ARGUMENT;
    }
    if (!raze_vint_decode(buf, len, &consumed, &hash_type)) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }
    if (hash_type != RAZE_RAR5_FHEXTRA_HASH_BLAKE2SP) {
        return RAZE_STATUS_UNSUPPORTED_FEATURE;
    }
    if (len - consumed != RAZE_RAR5_BLAKE2SP_DIGEST_SIZE) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }

    memcpy(file_header->hash_value, buf + consumed, RAZE_RAR5_BLAKE2SP_DIGEST_SIZE);
    file_header->hash_present = 1;
    file_header->hash_type = RAZE_RAR5_HASH_TYPE_BLAKE2SP;
    file_header->hash_is_packed_part = file_header->split_after ? 1 : 0;
    return RAZE_STATUS_OK;
}

static RazeStatus parse_file_extras(
    const unsigned char *buf,
    size_t extra_len,
    RazeRar5FileHeader *file_header
) {
    size_t cursor = 0;

    while (cursor < extra_len) {
        uint64_t field_size = 0;
        uint64_t field_type = 0;
        size_t consumed = 0;
        size_t next_pos;
        RazeStatus status;

        if (!raze_vint_decode(buf + cursor, extra_len - cursor, &consumed, &field_size)) {
            return RAZE_STATUS_BAD_ARCHIVE;
        }
        if ((size_t)field_size > SIZE_MAX - cursor) {
            return RAZE_STATUS_BAD_ARCHIVE;
        }
        cursor += consumed;
        if (field_size == 0 || field_size > extra_len - cursor) {
            return RAZE_STATUS_BAD_ARCHIVE;
        }

        next_pos = cursor + (size_t)field_size;
        if (!raze_vint_decode(buf + cursor, next_pos - cursor, &consumed, &field_type)) {
            return RAZE_STATUS_BAD_ARCHIVE;
        }
        cursor += consumed;

        if (field_type == RAZE_RAR5_FHEXTRA_CRYPT) {
            status = parse_crypt_extra(buf + cursor, next_pos - cursor, file_header);
            if (status != RAZE_STATUS_OK) {
                return status;
            }
            file_header->encrypted = 1;
        } else if (field_type == RAZE_RAR5_FHEXTRA_HASH) {
            status = parse_hash_extra(buf + cursor, next_pos - cursor, file_header);
            if (status != RAZE_STATUS_OK) {
                return status;
            }
        }
        cursor = next_pos;
    }

    return RAZE_STATUS_OK;
}

static int compute_dict_size(
    uint64_t comp_version,
    uint64_t dict_base_log2,
    uint64_t dict_extra_scale,
    uint64_t *dict_size_out
) {
    uint64_t base;
    uint64_t extra;

    if (dict_size_out == 0) {
        return 0;
    }

    if (comp_version == 0) {
        if (dict_base_log2 > 15U || dict_extra_scale != 0U) {
            return 0;
        }
    } else if (comp_version == 1) {
        if (dict_base_log2 > 23U || dict_extra_scale > 31U) {
            return 0;
        }
    } else {
        return 1;
    }

    if (dict_base_log2 > 46U) {
        return 0;
    }

    base = (uint64_t)RAZE_RAR5_DICT_BASE_BYTES << dict_base_log2;
    extra = (base * dict_extra_scale) / 32U;
    if (extra > UINT64_MAX - base) {
        return 0;
    }

    *dict_size_out = base + extra;
    return 1;
}

RazeStatus raze_rar5_parse_file_header(
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
    RazeStatus status = RAZE_STATUS_OK;

    if (block == 0 || buf == 0 || file_header == 0) {
        return RAZE_STATUS_BAD_ARGUMENT;
    }
    if (block->extra_offset > buf_len || block->body_offset > block->extra_offset) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }

    memset(file_header, 0, sizeof(*file_header));
    file_header->pack_size = block->data_size;
    file_header->split_before = (block->flags & RAZE_RAR5_HFL_SPLITBEFORE) != 0;
    file_header->split_after = (block->flags & RAZE_RAR5_HFL_SPLITAFTER) != 0;
    cursor = block->body_offset;

    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &file_header->file_flags)) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }
    cursor += consumed;

    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &file_header->unp_size)) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }
    cursor += consumed;

    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &file_header->file_attr)) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }
    cursor += consumed;

    if ((file_header->file_flags & RAZE_RAR5_FHFL_UTIME) != 0) {
        if (block->extra_offset - cursor < 4) {
            return RAZE_STATUS_BAD_ARCHIVE;
        }
        file_header->unix_mtime = read_u32le(buf + cursor);
        file_header->mtime_present = 1;
        cursor += 4;
    }

    if ((file_header->file_flags & RAZE_RAR5_FHFL_CRC32) != 0) {
        if (block->extra_offset - cursor < 4) {
            return RAZE_STATUS_BAD_ARCHIVE;
        }
        memcpy(crc_raw, buf + cursor, sizeof(crc_raw));
        file_header->crc32 = read_u32le(crc_raw);
        file_header->crc32_present = 1;
        cursor += 4;
    }

    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &comp_info)) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }
    cursor += consumed;

    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &file_header->host_os)) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }
    cursor += consumed;

    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &name_len)) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }
    cursor += consumed;

    if (name_len == 0 || name_len > block->extra_offset - cursor || name_len >= (uint64_t)SIZE_MAX) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }
    if (memchr(buf + cursor, '\0', (size_t)name_len) != 0) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }

    file_header->name = (char *)malloc((size_t)name_len + 1U);
    if (file_header->name == 0) {
        return RAZE_STATUS_IO;
    }
    memcpy(file_header->name, buf + cursor, (size_t)name_len);
    file_header->name[(size_t)name_len] = '\0';
    file_header->name_len = (size_t)name_len;
    cursor += (size_t)name_len;

    file_header->comp_version = comp_info & RAZE_RAR5_FCI_VERSION_MASK;
    file_header->method = (comp_info & RAZE_RAR5_FCI_METHOD_MASK) >> 7U;
    file_header->dict_base_log2 = (comp_info & RAZE_RAR5_FCI_DICT_BASE_MASK) >> 10U;
    file_header->dict_extra_scale = (comp_info & RAZE_RAR5_FCI_DICT_EXTRA_MASK) >> 15U;
    file_header->comp_is_v50_compat = (comp_info & RAZE_RAR5_FCI_V50_COMPAT) != 0;
    file_header->solid = (comp_info & RAZE_RAR5_FCI_SOLID) != 0;
    file_header->is_dir = (file_header->file_flags & RAZE_RAR5_FHFL_DIRECTORY) != 0;
    if (file_header->comp_version != 1 && file_header->comp_is_v50_compat) {
        status = RAZE_STATUS_BAD_ARCHIVE;
        goto fail;
    }
    if (!compute_dict_size(
            file_header->comp_version,
            file_header->dict_base_log2,
            file_header->dict_extra_scale,
            &file_header->dict_size_bytes
        )) {
        status = RAZE_STATUS_BAD_ARCHIVE;
        goto fail;
    }

    if (block->extra_size > 0) {
        const unsigned char *extra_ptr = buf + block->extra_offset;
        status = parse_file_extras(extra_ptr, (size_t)block->extra_size, file_header);
        if (status != RAZE_STATUS_OK) {
            goto fail;
        }
    }

    if (cursor > buf_len) {
        status = RAZE_STATUS_BAD_ARCHIVE;
        goto fail;
    }

    return RAZE_STATUS_OK;

fail:
    raze_rar5_file_header_free(file_header);
    return status;
}

void raze_rar5_file_header_free(RazeRar5FileHeader *file_header) {
    if (file_header == 0) {
        return;
    }
    free(file_header->name);
    file_header->name = 0;
    file_header->name_len = 0;
}
