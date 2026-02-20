#include "copy_kernels.h"

#include <stdint.h>
#include <string.h>

#include "../../platform/cpu_features.h"

#if (defined(__x86_64__) || defined(__i386__)) && \
	(defined(__GNUC__) || defined(__clang__))
#define RAZE_RAR5_HAVE_X86_INTRINSICS 1
#include <immintrin.h>
#define RAZE_RAR5_TARGET_AVX2 __attribute__((target("avx2")))
#define RAZE_RAR5_TARGET_SSE2 __attribute__((target("sse2")))
#else
#define RAZE_RAR5_HAVE_X86_INTRINSICS 0
#define RAZE_RAR5_TARGET_AVX2
#define RAZE_RAR5_TARGET_SSE2
#endif

static void copy_overlap_scalar(
	unsigned char *dst,
	size_t length,
	size_t distance
)
{
	unsigned char *src = dst - distance;

	if (distance == 0U || length == 0U) {
		return;
	}

	if (distance >= length) {
		memcpy(dst, src, length);
		return;
	}

	while (length >= 8U) {
		dst[0] = src[0];
		dst[1] = src[1];
		dst[2] = src[2];
		dst[3] = src[3];
		dst[4] = src[4];
		dst[5] = src[5];
		dst[6] = src[6];
		dst[7] = src[7];
		dst += 8U;
		src += 8U;
		length -= 8U;
	}
	while (length > 0U) {
		*dst++ = *src++;
		length -= 1U;
	}
}

static void fill_repeat2_scalar(
	unsigned char *dst,
	size_t length,
	unsigned char b0,
	unsigned char b1
)
{
	size_t i;

	while (length >= 8U) {
		dst[0] = b0;
		dst[1] = b1;
		dst[2] = b0;
		dst[3] = b1;
		dst[4] = b0;
		dst[5] = b1;
		dst[6] = b0;
		dst[7] = b1;
		dst += 8U;
		length -= 8U;
	}
	for (i = 0U; i < length; ++i) {
		dst[i] = (i & 1U) != 0U ? b1 : b0;
	}
}

static void fill_repeat4_scalar(
	unsigned char *dst,
	size_t length,
	const unsigned char p[4]
)
{
	size_t i;

	while (length >= 8U) {
		dst[0] = p[0];
		dst[1] = p[1];
		dst[2] = p[2];
		dst[3] = p[3];
		dst[4] = p[0];
		dst[5] = p[1];
		dst[6] = p[2];
		dst[7] = p[3];
		dst += 8U;
		length -= 8U;
	}
	for (i = 0U; i < length; ++i) {
		dst[i] = p[i & 3U];
	}
}

#if RAZE_RAR5_HAVE_X86_INTRINSICS
static RAZE_RAR5_TARGET_SSE2 void copy_overlap_sse2(
	unsigned char *dst,
	size_t length,
	size_t distance
)
{
	unsigned char *src = dst - distance;

	if (distance == 0U || length == 0U) {
		return;
	}
	if (distance >= length) {
		memcpy(dst, src, length);
		return;
	}
	if (distance < 16U) {
		copy_overlap_scalar(dst, length, distance);
		return;
	}

	while (length >= 16U) {
		__m128i v = _mm_loadu_si128((const __m128i *)src);
		_mm_storeu_si128((__m128i *)dst, v);
		dst += 16U;
		src += 16U;
		length -= 16U;
	}
	if (length > 0U) {
		copy_overlap_scalar(dst, length, distance);
	}
}

static RAZE_RAR5_TARGET_SSE2 void fill_repeat2_sse2(
	unsigned char *dst,
	size_t length,
	unsigned char b0,
	unsigned char b1
)
{
	uint16_t pair = (uint16_t)b0 | ((uint16_t)b1 << 8U);
	__m128i v = _mm_set1_epi16((short)pair);

	while (length >= 16U) {
		_mm_storeu_si128((__m128i *)dst, v);
		dst += 16U;
		length -= 16U;
	}
	if (length > 0U) {
		fill_repeat2_scalar(dst, length, b0, b1);
	}
}

static RAZE_RAR5_TARGET_SSE2 void fill_repeat4_sse2(
	unsigned char *dst,
	size_t length,
	const unsigned char p[4]
)
{
	uint32_t quad = (uint32_t)p[0] |
			((uint32_t)p[1] << 8U) |
			((uint32_t)p[2] << 16U) |
			((uint32_t)p[3] << 24U);
	__m128i v = _mm_set1_epi32((int)quad);

	while (length >= 16U) {
		_mm_storeu_si128((__m128i *)dst, v);
		dst += 16U;
		length -= 16U;
	}
	if (length > 0U) {
		fill_repeat4_scalar(dst, length, p);
	}
}

static RAZE_RAR5_TARGET_AVX2 void copy_overlap_avx2(
	unsigned char *dst,
	size_t length,
	size_t distance
)
{
	unsigned char *src = dst - distance;

	if (distance == 0U || length == 0U) {
		return;
	}
	if (distance >= length) {
		memcpy(dst, src, length);
		return;
	}
	if (distance < 32U) {
		copy_overlap_sse2(dst, length, distance);
		return;
	}

	while (length >= 32U) {
		__m256i v = _mm256_loadu_si256((const __m256i *)src);
		_mm256_storeu_si256((__m256i *)dst, v);
		dst += 32U;
		src += 32U;
		length -= 32U;
	}
	if (length > 0U) {
		copy_overlap_sse2(dst, length, distance);
	}
}

static RAZE_RAR5_TARGET_AVX2 void fill_repeat2_avx2(
	unsigned char *dst,
	size_t length,
	unsigned char b0,
	unsigned char b1
)
{
	uint16_t pair = (uint16_t)b0 | ((uint16_t)b1 << 8U);
	__m256i v = _mm256_set1_epi16((short)pair);

	while (length >= 32U) {
		_mm256_storeu_si256((__m256i *)dst, v);
		dst += 32U;
		length -= 32U;
	}
	if (length > 0U) {
		fill_repeat2_sse2(dst, length, b0, b1);
	}
}

static RAZE_RAR5_TARGET_AVX2 void fill_repeat4_avx2(
	unsigned char *dst,
	size_t length,
	const unsigned char p[4]
)
{
	uint32_t quad = (uint32_t)p[0] |
			((uint32_t)p[1] << 8U) |
			((uint32_t)p[2] << 16U) |
			((uint32_t)p[3] << 24U);
	__m256i v = _mm256_set1_epi32((int)quad);

	while (length >= 32U) {
		_mm256_storeu_si256((__m256i *)dst, v);
		dst += 32U;
		length -= 32U;
	}
	if (length > 0U) {
		fill_repeat4_sse2(dst, length, p);
	}
}
#endif

const RazeRar5CopyKernels *raze_rar5_copy_kernels_get(void)
{
	static RazeRar5CopyKernels kernels;
	static int initialized;

	if (initialized) {
		return &kernels;
	}

	kernels.copy_overlap = copy_overlap_scalar;
	kernels.fill_repeat2 = fill_repeat2_scalar;
	kernels.fill_repeat4 = fill_repeat4_scalar;

#if RAZE_RAR5_HAVE_X86_INTRINSICS
	{
		const RazeCpuFeatures *features = raze_cpu_features_get();
		if (features->x86_avx2) {
			kernels.copy_overlap = copy_overlap_avx2;
			kernels.fill_repeat2 = fill_repeat2_avx2;
			kernels.fill_repeat4 = fill_repeat4_avx2;
		} else if (features->x86_sse2) {
			kernels.copy_overlap = copy_overlap_sse2;
			kernels.fill_repeat2 = fill_repeat2_sse2;
			kernels.fill_repeat4 = fill_repeat4_sse2;
		}
	}
#endif

	initialized = 1;
	return &kernels;
}
