#ifndef RAZE_RAZE_H
#define RAZE_RAZE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RazeDecoder {
    int initialized;
} RazeDecoder;

typedef enum RazeOverwriteMode {
    RAZE_OVERWRITE_DEFAULT = 0,
    RAZE_OVERWRITE_ALWAYS = 1,
    RAZE_OVERWRITE_NEVER = 2
} RazeOverwriteMode;

typedef struct RazeExtractOptions {
    RazeOverwriteMode overwrite_mode;
    int quiet;
    int verbose;
    const char *password;
    int password_present;
    int strip_paths;
    int ad_mode;
    int recurse;
    const char *ap_prefix;
    const char *const *include_masks;
    size_t include_mask_count;
    const char *const *exclude_masks;
    size_t exclude_mask_count;
    int test_only;
    int print_stdout;
} RazeExtractOptions;

typedef enum RazeStatus {
    RAZE_STATUS_OK = 0,
    RAZE_STATUS_ERROR = 1,
    RAZE_STATUS_BAD_ARGUMENT = 2,
    RAZE_STATUS_UNSUPPORTED = 3,
    RAZE_STATUS_UNSUPPORTED_FEATURE = 4,
    RAZE_STATUS_BAD_ARCHIVE = 5,
    RAZE_STATUS_PATH_VIOLATION = 6,
    RAZE_STATUS_CRC_MISMATCH = 7,
    RAZE_STATUS_EXISTS = 8,
    RAZE_STATUS_IO = 9,
    RAZE_STATUS_ABORTED = 10
} RazeStatus;

RazeStatus raze_decoder_init(RazeDecoder *decoder);
RazeExtractOptions raze_extract_options_default(void);
RazeStatus raze_decode_archive(
    RazeDecoder *decoder,
    const char *archive_path,
    const char *output_dir
);
RazeStatus raze_decode_archive_with_options(
    RazeDecoder *decoder,
    const char *archive_path,
    const char *output_dir,
    const RazeExtractOptions *options
);
RazeStatus raze_list_archive(
    RazeDecoder *decoder,
    const char *archive_path,
    int technical
);
RazeStatus raze_list_archive_with_options(
    RazeDecoder *decoder,
    const char *archive_path,
    int technical,
    const RazeExtractOptions *options
);
const char *raze_status_string(RazeStatus status);
const char *raze_last_error_detail(void);
void raze_clear_error_detail(void);

#ifdef __cplusplus
}
#endif

#endif
