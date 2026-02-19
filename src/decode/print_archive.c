#include "print_archive.h"

#include "extract_store.h"

RazeStatus raze_print_archive(
	const char *archive_path,
	const RazeExtractOptions *options
)
{
	RazeExtractOptions local;

	if (archive_path == 0) {
		return RAZE_STATUS_BAD_ARGUMENT;
	}
	if (options == 0) {
		local = raze_extract_options_default();
		options = &local;
	}
	local = *options;
	local.test_only = 0;
	local.print_stdout = 1;
	return raze_extract_store_archive(archive_path, ".", &local);
}
