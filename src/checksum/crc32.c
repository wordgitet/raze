#include "crc32.h"

#ifdef RAZE_USE_ISAL
#include "crc.h"
#endif

#ifndef RAZE_USE_ISAL
static uint32_t crc32_table[256];
static int crc32_table_ready = 0;

static void crc32_init_table(void) {
    uint32_t i;

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
        crc32_table[i] = c;
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

    for (i = 0; i < len; ++i) {
        crc = crc32_table[(crc ^ bytes[i]) & 0xFFU] ^ (crc >> 8U);
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
