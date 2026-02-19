#ifdef _WIN32

#include "time.h"

#include <windows.h>

uint64_t raze_platform_monotonic_ns(void)
{
	LARGE_INTEGER freq;
	LARGE_INTEGER ctr;

	if (!QueryPerformanceFrequency(&freq) || !QueryPerformanceCounter(&ctr) ||
	    freq.QuadPart == 0) {
		return 0U;
	}
	return (uint64_t)((ctr.QuadPart * 1000000000ULL) / freq.QuadPart);
}

#else
typedef int raze_win_time_unused_t;
#endif
