#ifndef RAZE_PLATFORM_CPU_FEATURES_H
#define RAZE_PLATFORM_CPU_FEATURES_H

typedef struct RazeCpuFeatures {
	int x86_sse2;
	int x86_avx2;
	int x86_bmi2;
} RazeCpuFeatures;

const RazeCpuFeatures *raze_cpu_features_get(void);

#endif
