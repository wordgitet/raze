#ifndef RAZE_FORMAT_RAR5_VINT_H
#define RAZE_FORMAT_RAR5_VINT_H

#include <stddef.h>
#include <stdint.h>

int raze_vint_decode(
    const unsigned char *buf,
    size_t buf_len,
    size_t *consumed,
    uint64_t *value
);

#endif
