#ifndef RAZE_IO_VOLUME_CHAIN_H
#define RAZE_IO_VOLUME_CHAIN_H

#include <stddef.h>

#include "raze/raze.h"

typedef struct RazeVolumeChain {
	char **paths;
	size_t count;
	size_t capacity;
} RazeVolumeChain;

void raze_volume_chain_free(RazeVolumeChain *chain);
RazeStatus raze_volume_chain_discover(const char *first_volume_path, RazeVolumeChain *chain);

#endif
