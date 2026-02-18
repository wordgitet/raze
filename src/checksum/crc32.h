#ifndef RAZE_CHECKSUM_CRC32_H
#define RAZE_CHECKSUM_CRC32_H

#include <stddef.h>
#include <stdint.h>

uint32_t raze_crc32_init(void);
uint32_t raze_crc32_update(uint32_t crc, const void *data, size_t len);
uint32_t raze_crc32_final(uint32_t crc);
uint32_t raze_crc32_bytes(const void *data, size_t len);
int raze_crc32_selftest(void);

#endif
