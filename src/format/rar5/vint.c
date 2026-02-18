#include "vint.h"

int raze_vint_decode(
    const unsigned char *buf,
    size_t buf_len,
    size_t *consumed,
    uint64_t *value
) {
    size_t i;
    uint64_t out = 0;
    unsigned int shift = 0;

    if (buf == 0 || consumed == 0 || value == 0) {
        return 0;
    }

    for (i = 0; i < buf_len && i < 10; ++i) {
        unsigned char cur = buf[i];
        uint64_t part = (uint64_t)(cur & 0x7FU);

        if (i == 9) {
            /* 10th byte can carry only one payload bit for uint64. */
            if ((cur & 0x80U) != 0 || (cur & 0x7EU) != 0) {
                return 0;
            }
        }

        if (shift >= 64) {
            return 0;
        }
        if (shift == 63 && part > 1U) {
            return 0;
        }

        out |= part << shift;
        if ((cur & 0x80U) == 0) {
            *consumed = i + 1;
            *value = out;
            return 1;
        }
        shift += 7;
    }

    return 0;
}
