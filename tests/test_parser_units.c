#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "../src/checksum/crc32.h"
#include "../src/format/rar5/block_reader.h"
#include "../src/format/rar5/file_header.h"
#include "../src/format/rar5/vint.h"
#include "../src/io/fs_meta.h"

static void write_u32le(unsigned char *dst, uint32_t value) {
    dst[0] = (unsigned char)(value & 0xFFU);
    dst[1] = (unsigned char)((value >> 8U) & 0xFFU);
    dst[2] = (unsigned char)((value >> 16U) & 0xFFU);
    dst[3] = (unsigned char)((value >> 24U) & 0xFFU);
}

static int append_vint(unsigned char *dst, size_t dst_len, size_t *cursor, uint64_t value) {
    size_t pos = *cursor;

    do {
        unsigned char byte = (unsigned char)(value & 0x7FU);
        value >>= 7U;
        if (value != 0) {
            byte |= 0x80U;
        }
        if (pos >= dst_len) {
            return 0;
        }
        dst[pos++] = byte;
    } while (value != 0);

    *cursor = pos;
    return 1;
}

static int build_file_header_payload(
    unsigned char *buf,
    size_t buf_cap,
    RazeRar5BlockHeader *block,
    uint64_t comp_info,
    int bad_name_len,
    int add_crypt_extra,
    size_t *payload_len
) {
    const char name[] = "file.txt";
    uint64_t name_len = (uint64_t)(sizeof(name) - 1U);
    size_t cursor = 0;
    size_t name_copy_len;

    if (buf == 0 || block == 0 || payload_len == 0) {
        return 0;
    }

    memset(block, 0, sizeof(*block));

    if (bad_name_len) {
        name_len += 10U;
    }

    if (!append_vint(buf, buf_cap, &cursor, 0U)) {
        return 0;
    }
    if (!append_vint(buf, buf_cap, &cursor, 11U)) {
        return 0;
    }
    if (!append_vint(buf, buf_cap, &cursor, 0644U)) {
        return 0;
    }
    if (!append_vint(buf, buf_cap, &cursor, comp_info)) {
        return 0;
    }
    if (!append_vint(buf, buf_cap, &cursor, RAZE_RAR5_HOST_OS_UNIX)) {
        return 0;
    }
    if (!append_vint(buf, buf_cap, &cursor, name_len)) {
        return 0;
    }

    name_copy_len = sizeof(name) - 1U;
    if (cursor + name_copy_len > buf_cap) {
        return 0;
    }
    memcpy(buf + cursor, name, name_copy_len);
    cursor += name_copy_len;

    block->header_type = 2U;
    block->data_size = 11U;
    block->body_offset = 0U;

    if (add_crypt_extra) {
        size_t extra_start = cursor;
        size_t field_size_pos;
        size_t payload_start;

        if (cursor + 64U > buf_cap) {
            return 0;
        }
        block->flags = 0x0001U;
        block->extra_offset = cursor;

        field_size_pos = cursor++;
        if (!append_vint(buf, buf_cap, &cursor, 0x01U)) {
            return 0;
        }

        payload_start = cursor;
        if (!append_vint(buf, buf_cap, &cursor, 0U)) {
            return 0;
        }
        if (!append_vint(buf, buf_cap, &cursor, 0U)) {
            return 0;
        }
        buf[cursor++] = 15U;
        memset(buf + cursor, 0x11, 16U);
        cursor += 16U;
        memset(buf + cursor, 0x22, 16U);
        cursor += 16U;

        buf[field_size_pos] = (unsigned char)(1U + (cursor - payload_start));
        block->extra_size = cursor - extra_start;
    } else {
        block->extra_offset = cursor;
        block->extra_size = 0U;
    }

    *payload_len = cursor;
    return 1;
}

static int test_vint_valid(void) {
    unsigned char raw[] = {0xAC, 0x02};
    size_t consumed = 0;
    uint64_t value = 0;
    return raze_vint_decode(raw, sizeof(raw), &consumed, &value) &&
           consumed == 2 && value == 300U;
}

static int test_vint_truncated(void) {
    unsigned char raw[] = {0x80};
    size_t consumed = 0;
    uint64_t value = 0;
    return !raze_vint_decode(raw, sizeof(raw), &consumed, &value);
}

static int test_vint_overflow(void) {
    unsigned char raw[] = {
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02
    };
    size_t consumed = 0;
    uint64_t value = 0;
    return !raze_vint_decode(raw, sizeof(raw), &consumed, &value);
}

static int test_signature_with_sfx_prefix(void) {
    FILE *f = tmpfile();
    unsigned char prefix[32];
    unsigned char sig[8] = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00};
    RazeStatus status;

    if (f == 0) {
        return 0;
    }

    memset(prefix, 0xAA, sizeof(prefix));
    if (fwrite(prefix, 1, sizeof(prefix), f) != sizeof(prefix)) {
        fclose(f);
        return 0;
    }
    if (fwrite(sig, 1, sizeof(sig), f) != sizeof(sig)) {
        fclose(f);
        return 0;
    }
    if (fflush(f) != 0) {
        fclose(f);
        return 0;
    }

    status = raze_rar5_read_signature(f);
    fclose(f);
    return status == RAZE_STATUS_OK;
}

static int build_endarc_block(unsigned char *out, size_t out_len, int break_crc, size_t *written) {
    unsigned char header_data[2] = {0x05, 0x00};
    unsigned char size_raw[1] = {0x02};
    uint32_t crc;

    if (out == 0 || out_len < 7 || written == 0) {
        return 0;
    }

    crc = raze_crc32_init();
    crc = raze_crc32_update(crc, size_raw, sizeof(size_raw));
    crc = raze_crc32_update(crc, header_data, sizeof(header_data));
    crc = raze_crc32_final(crc);
    if (break_crc) {
        crc ^= 0xFFFFFFFFU;
    }

    write_u32le(out, crc);
    out[4] = size_raw[0];
    out[5] = header_data[0];
    out[6] = header_data[1];
    *written = 7;
    return 1;
}

static int test_block_crc_ok(void) {
    unsigned char raw[16];
    size_t raw_len = 0;
    FILE *f;
    RazeRar5BlockHeader block;
    unsigned char *header_buf = 0;
    size_t header_buf_len = 0;
    RazeStatus status = RAZE_STATUS_ERROR;
    RazeRar5ReadResult rr;
    int ok = 0;

    if (!build_endarc_block(raw, sizeof(raw), 0, &raw_len)) {
        return 0;
    }

    f = tmpfile();
    if (f == 0) {
        return 0;
    }
    if (fwrite(raw, 1, raw_len, f) != raw_len) {
        fclose(f);
        return 0;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return 0;
    }

    rr = raze_rar5_read_block(f, &block, &header_buf, &header_buf_len, &status);
    ok = rr == RAZE_RAR5_READ_OK &&
         status == RAZE_STATUS_OK &&
         block.header_type == 5U &&
         block.flags == 0U &&
         block.data_size == 0U &&
         header_buf_len == 2U;

    free(header_buf);
    fclose(f);
    return ok;
}

static int test_block_crc_bad(void) {
    unsigned char raw[16];
    size_t raw_len = 0;
    FILE *f;
    RazeRar5BlockHeader block;
    unsigned char *header_buf = 0;
    size_t header_buf_len = 0;
    RazeStatus status = RAZE_STATUS_ERROR;
    RazeRar5ReadResult rr;
    int ok = 0;

    if (!build_endarc_block(raw, sizeof(raw), 1, &raw_len)) {
        return 0;
    }

    f = tmpfile();
    if (f == 0) {
        return 0;
    }
    if (fwrite(raw, 1, raw_len, f) != raw_len) {
        fclose(f);
        return 0;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return 0;
    }

    rr = raze_rar5_read_block(f, &block, &header_buf, &header_buf_len, &status);
    ok = rr == RAZE_RAR5_READ_ERROR && status == RAZE_STATUS_BAD_ARCHIVE;

    free(header_buf);
    fclose(f);
    return ok;
}

static int test_file_header_valid(void) {
    unsigned char payload[128];
    size_t payload_len = 0;
    RazeRar5BlockHeader block;
    RazeRar5FileHeader fh;
    int ok = 0;

    if (!build_file_header_payload(payload, sizeof(payload), &block, 0U, 0, 0, &payload_len)) {
        return 0;
    }

    if (!raze_rar5_parse_file_header(&block, payload, payload_len, &fh)) {
        return 0;
    }

    ok = fh.file_attr == 0644U &&
         fh.method == 0U &&
         fh.comp_version == 0U &&
         fh.dict_base_log2 == 0U &&
         fh.dict_extra_scale == 0U &&
         fh.dict_size_bytes == (128U * 1024U) &&
         fh.comp_is_v50_compat == 0 &&
         fh.unp_size == 11U &&
         fh.pack_size == 11U &&
         fh.host_os == RAZE_RAR5_HOST_OS_UNIX &&
         fh.encrypted == 0 &&
         fh.name != 0 &&
         strcmp(fh.name, "file.txt") == 0;

    raze_rar5_file_header_free(&fh);
    return ok;
}

static int test_file_header_truncated(void) {
    unsigned char payload[128];
    size_t payload_len = 0;
    RazeRar5BlockHeader block;
    RazeRar5FileHeader fh;

    if (!build_file_header_payload(payload, sizeof(payload), &block, 0U, 0, 0, &payload_len)) {
        return 0;
    }

    return !raze_rar5_parse_file_header(&block, payload, payload_len - 1U, &fh);
}

static int test_file_header_bad_name_len(void) {
    unsigned char payload[128];
    size_t payload_len = 0;
    RazeRar5BlockHeader block;
    RazeRar5FileHeader fh;

    if (!build_file_header_payload(payload, sizeof(payload), &block, 0U, 1, 0, &payload_len)) {
        return 0;
    }

    return !raze_rar5_parse_file_header(&block, payload, payload_len, &fh);
}

static int test_file_header_crypt_extra(void) {
    unsigned char payload[128];
    size_t payload_len = 0;
    RazeRar5BlockHeader block;
    RazeRar5FileHeader fh;
    int ok = 0;

    if (!build_file_header_payload(payload, sizeof(payload), &block, 0U, 0, 1, &payload_len)) {
        return 0;
    }

    if (!raze_rar5_parse_file_header(&block, payload, payload_len, &fh)) {
        return 0;
    }

    ok = fh.encrypted == 1;
    raze_rar5_file_header_free(&fh);
    return ok;
}

static int test_fs_meta_mode_mapping(void) {
    mode_t mask;
    mode_t mode;
    mode_t expected;

    mask = umask(022);
    umask(mask);

    if (!raze_fs_compute_mode(RAZE_RAR5_HOST_OS_UNIX, 0754U, 0, &mode)) {
        return 0;
    }
    if ((mode & 07777) != 0754U) {
        return 0;
    }

    if (!raze_fs_compute_mode(RAZE_RAR5_HOST_OS_WINDOWS, 0x10U, 1, &mode)) {
        return 0;
    }
    expected = (mode_t)(0777 & ~mask);
    if ((mode & 0777) != (expected & 0777)) {
        return 0;
    }

    if (!raze_fs_compute_mode(RAZE_RAR5_HOST_OS_WINDOWS, 0x01U, 0, &mode)) {
        return 0;
    }
    expected = (mode_t)(0444 & ~mask);
    if ((mode & 0777) != (expected & 0777)) {
        return 0;
    }

    if (!raze_fs_compute_mode(RAZE_RAR5_HOST_OS_WINDOWS, 0x00U, 0, &mode)) {
        return 0;
    }
    expected = (mode_t)(0666 & ~mask);
    if ((mode & 0777) != (expected & 0777)) {
        return 0;
    }

    return 1;
}

static int test_file_header_v70_dict_info(void) {
	unsigned char payload[128];
	size_t payload_len = 0;
	RazeRar5BlockHeader block;
	RazeRar5FileHeader fh;
	uint64_t comp_info;
	int ok = 0;

	comp_info = 1U;
	comp_info |= 2U << 7U;
	comp_info |= 4U << 10U;
	comp_info |= 16U << 15U;

	if (!build_file_header_payload(payload, sizeof(payload), &block, comp_info, 0, 0, &payload_len)) {
		return 0;
	}
	if (!raze_rar5_parse_file_header(&block, payload, payload_len, &fh)) {
		return 0;
	}

	ok = fh.comp_version == 1U &&
	     fh.method == 2U &&
	     fh.dict_base_log2 == 4U &&
	     fh.dict_extra_scale == 16U &&
	     fh.dict_size_bytes == 3145728U &&
	     fh.comp_is_v50_compat == 0;

	raze_rar5_file_header_free(&fh);
	return ok;
}

static int test_file_header_invalid_comp_info(void) {
	unsigned char payload[128];
	size_t payload_len = 0;
	RazeRar5BlockHeader block;
	RazeRar5FileHeader fh;
	uint64_t comp_info;

	comp_info = 0U;
	comp_info |= 1U << 15U;
	if (!build_file_header_payload(payload, sizeof(payload), &block, comp_info, 0, 0, &payload_len)) {
		return 0;
	}

	return !raze_rar5_parse_file_header(&block, payload, payload_len, &fh);
}

int main(void) {
    if (!test_vint_valid()) {
        return 1;
    }
    if (!test_vint_truncated()) {
        return 2;
    }
    if (!test_vint_overflow()) {
        return 3;
    }
    if (!test_signature_with_sfx_prefix()) {
        return 4;
    }
    if (!test_block_crc_ok()) {
        return 5;
    }
    if (!test_block_crc_bad()) {
        return 6;
    }
    if (!test_file_header_valid()) {
        return 7;
    }
    if (!test_file_header_truncated()) {
        return 8;
    }
    if (!test_file_header_bad_name_len()) {
        return 9;
    }
    if (!test_file_header_crypt_extra()) {
        return 10;
    }
    if (!test_fs_meta_mode_mapping()) {
        return 11;
    }
    if (!test_file_header_v70_dict_info()) {
        return 12;
    }
    if (!test_file_header_invalid_comp_info()) {
        return 13;
    }
    return 0;
}
