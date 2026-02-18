#ifndef RAZE_FORMAT_RAR5_BLOCK_READER_H
#define RAZE_FORMAT_RAR5_BLOCK_READER_H

#include <stdio.h>

#include "../../decode/decode_internal.h"

typedef enum RazeRar5ReadResult {
    RAZE_RAR5_READ_OK = 0,
    RAZE_RAR5_READ_EOF = 1,
    RAZE_RAR5_READ_ERROR = 2
} RazeRar5ReadResult;

RazeStatus raze_rar5_read_signature(FILE *file);
RazeRar5ReadResult raze_rar5_read_block(
    FILE *file,
    RazeRar5BlockHeader *block,
    unsigned char **header_buf,
    size_t *header_buf_len,
    RazeStatus *error_status
);

#endif
