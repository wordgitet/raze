#include "crc32.h"

#ifdef RAZE_USE_ISAL
#include "crc.h"
#endif

#ifndef RAZE_USE_ISAL
static uint32_t crc32_table[8][256];
static int crc32_table_ready = 0;

static void crc32_init_table(void) {
    uint32_t i;
    uint32_t k;

    for (i = 0; i < 256; ++i) {
        uint32_t c = i;
        int j;
        for (j = 0; j < 8; ++j) {
            if (c & 1U) {
                c = 0xEDB88320U ^ (c >> 1U);
            } else {
                c >>= 1U;
            }
        }
        crc32_table[0][i] = c;
    }

    for (k = 1; k < 8; ++k) {
        for (i = 0; i < 256; ++i) {
            uint32_t c = crc32_table[k - 1][i];
            crc32_table[k][i] =
                crc32_table[0][c & 0xFFU] ^ (c >> 8U);
        }
    }

    crc32_table_ready = 1;
}
#endif

uint32_t raze_crc32_init(void) {
#ifdef RAZE_USE_ISAL
    return 0xFFFFFFFFU;
#else
    if (!crc32_table_ready) {
        crc32_init_table();
    }
    return 0xFFFFFFFFU;
#endif
}

uint32_t raze_crc32_update(uint32_t crc, const void *data, size_t len) {
#ifdef RAZE_USE_ISAL
    uint32_t seed = crc ^ 0xFFFFFFFFU;
    uint32_t next = crc32_gzip_refl(seed, (const unsigned char *)data, (uint64_t)len);
    return next ^ 0xFFFFFFFFU;
#else
    const unsigned char *bytes = (const unsigned char *)data;
    size_t i;

    if (!crc32_table_ready) {
        crc32_init_table();
    }

    while (len >= 8U) {
        uint32_t one = ((uint32_t)bytes[0]) |
                       ((uint32_t)bytes[1] << 8U) |
                       ((uint32_t)bytes[2] << 16U) |
                       ((uint32_t)bytes[3] << 24U);
        uint32_t two = ((uint32_t)bytes[4]) |
                       ((uint32_t)bytes[5] << 8U) |
                       ((uint32_t)bytes[6] << 16U) |
                       ((uint32_t)bytes[7] << 24U);

        crc ^= one;
        crc = crc32_table[7][crc & 0xFFU] ^
              crc32_table[6][(crc >> 8U) & 0xFFU] ^
              crc32_table[5][(crc >> 16U) & 0xFFU] ^
              crc32_table[4][(crc >> 24U) & 0xFFU] ^
              crc32_table[3][two & 0xFFU] ^
              crc32_table[2][(two >> 8U) & 0xFFU] ^
              crc32_table[1][(two >> 16U) & 0xFFU] ^
              crc32_table[0][(two >> 24U) & 0xFFU];
        bytes += 8U;
        len -= 8U;
    }

    for (i = 0; i < len; ++i) {
        crc = crc32_table[0][(crc ^ bytes[i]) & 0xFFU] ^ (crc >> 8U);
    }

    return crc;
#endif
}

uint32_t raze_crc32_final(uint32_t crc) {
    return crc ^ 0xFFFFFFFFU;
}

uint32_t raze_crc32_bytes(const void *data, size_t len) {
    return raze_crc32_final(raze_crc32_update(raze_crc32_init(), data, len));
}

int raze_crc32_selftest(void) {
    static const char probe[] = "123456789";
    return raze_crc32_bytes(probe, 9) == 0xCBF43926U;
}
