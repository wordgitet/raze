#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/format/rar5/block_reader.h"
#include "../src/format/rar5/vint.h"
#include "../src/checksum/crc32.h"

static void write_u32le(unsigned char *dst, uint32_t value) {
    dst[0] = (unsigned char)(value & 0xFFU);
    dst[1] = (unsigned char)((value >> 8U) & 0xFFU);
    dst[2] = (unsigned char)((value >> 16U) & 0xFFU);
    dst[3] = (unsigned char)((value >> 24U) & 0xFFU);
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
    unsigned char header_data[2] = {0x05, 0x00}; /* type=HEAD_ENDARC, flags=0 */
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
    return 0;
}
