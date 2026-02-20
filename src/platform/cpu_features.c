#include "cpu_features.h"

#include <string.h>

const RazeCpuFeatures *raze_cpu_features_get(void)
{
	static RazeCpuFeatures features;
	static int initialized;

	if (initialized) {
		return &features;
	}

	memset(&features, 0, sizeof(features));

#if (defined(__x86_64__) || defined(__i386__)) && \
	(defined(__GNUC__) || defined(__clang__))
	__builtin_cpu_init();
	features.x86_sse2 = __builtin_cpu_supports("sse2") ? 1 : 0;
	features.x86_avx2 = __builtin_cpu_supports("avx2") ? 1 : 0;
	features.x86_bmi2 = __builtin_cpu_supports("bmi2") ? 1 : 0;
#endif

	initialized = 1;
	return &features;
}
