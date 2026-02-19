#ifndef _WIN32

#include "time.h"

#include <time.h>

uint64_t raze_platform_monotonic_ns(void)
{
	struct timespec ts;

	if (timespec_get(&ts, TIME_UTC) != TIME_UTC) {
		return 0U;
	}
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

#endif
