#include "raze/raze.h"

#include "decode_internal.h"
#include "extract_store.h"

RazeExtractOptions raze_extract_options_default(void) {
    RazeExtractOptions options;
    options.overwrite_mode = RAZE_OVERWRITE_DEFAULT;
    options.quiet = 0;
    options.verbose = 0;
    options.password = 0;
    options.password_present = 0;
    return options;
}

const char *raze_status_string(RazeStatus status) {
    switch (status) {
        case RAZE_STATUS_OK:
            return "ok";
        case RAZE_STATUS_ERROR:
            return "error";
        case RAZE_STATUS_BAD_ARGUMENT:
            return "bad argument";
        case RAZE_STATUS_UNSUPPORTED:
            return "unsupported archive";
        case RAZE_STATUS_UNSUPPORTED_FEATURE:
            return "unsupported feature";
        case RAZE_STATUS_BAD_ARCHIVE:
            return "bad archive";
        case RAZE_STATUS_PATH_VIOLATION:
            return "path violation";
        case RAZE_STATUS_CRC_MISMATCH:
            return "crc mismatch";
        case RAZE_STATUS_EXISTS:
            return "file exists";
        case RAZE_STATUS_IO:
            return "io error";
        case RAZE_STATUS_ABORTED:
            return "aborted";
        default:
            return "unknown";
    }
}

RazeStatus raze_decoder_init(RazeDecoder *decoder) {
    if (decoder == 0) {
        return RAZE_STATUS_BAD_ARGUMENT;
    }

    if (!raze_crc32_selftest() || !raze_crypto_selftest()) {
        return RAZE_STATUS_ERROR;
    }

    decoder->initialized = 1;
    return RAZE_STATUS_OK;
}

RazeStatus raze_decode_archive(
    RazeDecoder *decoder,
    const char *archive_path,
    const char *output_dir
) {
    RazeExtractOptions options = raze_extract_options_default();
    return raze_decode_archive_with_options(decoder, archive_path, output_dir, &options);
}

RazeStatus raze_decode_archive_with_options(
    RazeDecoder *decoder,
    const char *archive_path,
    const char *output_dir,
    const RazeExtractOptions *options
) {
    RazeExtractOptions local_options;

    if (decoder == 0 || archive_path == 0 || output_dir == 0) {
        return RAZE_STATUS_BAD_ARGUMENT;
    }

    if (!decoder->initialized) {
        return RAZE_STATUS_ERROR;
    }

    if (!raze_io_validate_input_path(archive_path)) {
        return RAZE_STATUS_IO;
    }

    if (options == 0) {
        local_options = raze_extract_options_default();
        options = &local_options;
    }

    return raze_extract_store_archive(archive_path, output_dir, options);
}

RazeStatus raze_list_archive(
    RazeDecoder *decoder,
    const char *archive_path,
    int technical
) {
    if (decoder == 0 || archive_path == 0) {
        return RAZE_STATUS_BAD_ARGUMENT;
    }

    if (!decoder->initialized) {
        return RAZE_STATUS_ERROR;
    }

    if (!raze_io_validate_input_path(archive_path)) {
        return RAZE_STATUS_IO;
    }

    return raze_list_rar5_archive(archive_path, technical);
}
