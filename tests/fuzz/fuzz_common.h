#ifndef RAZE_TESTS_FUZZ_COMMON_H
#define RAZE_TESTS_FUZZ_COMMON_H

#include <stddef.h>
#include <stdint.h>

#define RAZE_FUZZ_MAX_INPUT (1U << 20)
#define RAZE_FUZZ_MAX_OUTPUT (1U << 16)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#endif
