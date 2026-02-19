#include "raze/raze.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "decode_internal.h"
#include "extract_store.h"

#define RAZE_DIAG_MAX 512

static char raze_last_diag[RAZE_DIAG_MAX];

static int raze_diag_is_empty(void)
{
	return raze_last_diag[0] == '\0';
}

void raze_diag_set(const char *fmt, ...)
{
	va_list args;

	if (fmt == 0 || fmt[0] == '\0') {
		raze_last_diag[0] = '\0';
		return;
	}

	va_start(args, fmt);
	vsnprintf(raze_last_diag, sizeof(raze_last_diag), fmt, args);
	va_end(args);
}

const char *raze_last_error_detail(void)
{
	return raze_last_diag;
}

void raze_clear_error_detail(void)
{
	raze_last_diag[0] = '\0';
}

RazeExtractOptions raze_extract_options_default(void)
{
	RazeExtractOptions options;

	options.overwrite_mode = RAZE_OVERWRITE_DEFAULT;
	options.quiet = 0;
	options.verbose = 0;
	options.password = 0;
	options.password_present = 0;
	options.strip_paths = 0;
	options.ad_mode = 0;
	options.recurse = 0;
	options.ap_prefix = 0;
	options.include_masks = 0;
	options.include_mask_count = 0U;
	options.exclude_masks = 0;
	options.exclude_mask_count = 0U;
	options.test_only = 0;
	options.print_stdout = 0;
	return options;
}

const char *raze_status_string(RazeStatus status)
{
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

RazeStatus raze_decoder_init(RazeDecoder *decoder)
{
	if (decoder == 0) {
		raze_diag_set("decoder pointer is null");
		return RAZE_STATUS_BAD_ARGUMENT;
	}

	if (!raze_crc32_selftest()) {
		raze_diag_set("crc32 self-test failed");
		return RAZE_STATUS_ERROR;
	}
	if (!raze_crypto_selftest()) {
		raze_diag_set("crypto self-test failed");
		return RAZE_STATUS_ERROR;
	}

	decoder->initialized = 1;
	raze_clear_error_detail();
	return RAZE_STATUS_OK;
}

RazeStatus raze_decode_archive(
	RazeDecoder *decoder,
	const char *archive_path,
	const char *output_dir
)
{
	RazeExtractOptions options = raze_extract_options_default();

	return raze_decode_archive_with_options(decoder, archive_path, output_dir,
						&options);
}

RazeStatus raze_decode_archive_with_options(
	RazeDecoder *decoder,
	const char *archive_path,
	const char *output_dir,
	const RazeExtractOptions *options
)
{
	RazeExtractOptions local_options;
	RazeStatus status;

	raze_clear_error_detail();

	if (decoder == 0 || archive_path == 0 || output_dir == 0) {
		raze_diag_set("decoder, archive path, and output dir are required");
		return RAZE_STATUS_BAD_ARGUMENT;
	}

	if (!decoder->initialized) {
		raze_diag_set("decoder is not initialized");
		return RAZE_STATUS_ERROR;
	}

	if (!raze_io_validate_input_path(archive_path)) {
		raze_diag_set("input path is invalid: '%s'", archive_path);
		return RAZE_STATUS_IO;
	}

	if (options == 0) {
		local_options = raze_extract_options_default();
		options = &local_options;
	}

	status = raze_extract_store_archive(archive_path, output_dir, options);
	if (status != RAZE_STATUS_OK && raze_diag_is_empty()) {
		raze_diag_set("extract failed for '%s' into '%s'", archive_path,
			output_dir);
	}
	return status;
}

RazeStatus raze_list_archive(
	RazeDecoder *decoder,
	const char *archive_path,
	int technical
)
{
	return raze_list_archive_with_options(decoder, archive_path, technical,
					      0);
}

RazeStatus raze_list_archive_with_options(
	RazeDecoder *decoder,
	const char *archive_path,
	int technical,
	const RazeExtractOptions *options
)
{
	RazeStatus status;
	RazeExtractOptions local_options;

	raze_clear_error_detail();

	if (decoder == 0 || archive_path == 0) {
		raze_diag_set("decoder and archive path are required");
		return RAZE_STATUS_BAD_ARGUMENT;
	}

	if (!decoder->initialized) {
		raze_diag_set("decoder is not initialized");
		return RAZE_STATUS_ERROR;
	}

	if (!raze_io_validate_input_path(archive_path)) {
		raze_diag_set("input path is invalid: '%s'", archive_path);
		return RAZE_STATUS_IO;
	}

	if (options == 0) {
		local_options = raze_extract_options_default();
		options = &local_options;
	}

	status = raze_list_rar5_archive_with_options(archive_path, technical,
						     options);
	if (status != RAZE_STATUS_OK && raze_diag_is_empty()) {
		raze_diag_set("list failed for '%s'", archive_path);
	}
	return status;
}
