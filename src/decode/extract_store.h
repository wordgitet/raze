#ifndef RAZE_DECODE_EXTRACT_STORE_H
#define RAZE_DECODE_EXTRACT_STORE_H

#include "raze/raze.h"

RazeStatus raze_extract_store_archive(
    const char *archive_path,
    const char *output_dir,
    const RazeExtractOptions *options
);

#endif
