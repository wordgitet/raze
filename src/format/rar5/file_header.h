#ifndef RAZE_FORMAT_RAR5_FILE_HEADER_H
#define RAZE_FORMAT_RAR5_FILE_HEADER_H

#include <stddef.h>

#include "../../decode/decode_internal.h"

#define RAZE_RAR5_HOST_OS_WINDOWS 0U
#define RAZE_RAR5_HOST_OS_UNIX 1U

#define RAZE_RAR5_FHFL_DIRECTORY 0x0001U
#define RAZE_RAR5_FHFL_UTIME 0x0002U
#define RAZE_RAR5_FHFL_CRC32 0x0004U
#define RAZE_RAR5_FHFL_UNPUNKNOWN 0x0008U

RazeStatus raze_rar5_parse_file_header(
    const RazeRar5BlockHeader *block,
    const unsigned char *buf,
    size_t buf_len,
    RazeRar5FileHeader *file_header
);

void raze_rar5_file_header_free(RazeRar5FileHeader *file_header);

#endif
