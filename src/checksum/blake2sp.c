/*
 * Based on the BLAKE2 reference implementation originally released
 * by Samuel Neves under CC0/public-domain dedication.
 */

#include "blake2sp.h"

#include <string.h>

#define BLAKE2S_BLOCKBYTES 64U
#define BLAKE2S_OUTBYTES 32U

static const uint32_t blake2s_iv[8] = {
	0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
	0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U
};

static const unsigned char blake2s_sigma[10][16] = {
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
	{ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
	{  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
	{  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
	{  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
	{ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
	{ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
	{  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
	{ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 }
};

static uint32_t load32(const unsigned char *src)
{
	return ((uint32_t)src[0]) |
	       ((uint32_t)src[1] << 8) |
	       ((uint32_t)src[2] << 16) |
	       ((uint32_t)src[3] << 24);
}

static void store32(unsigned char *dst, uint32_t value)
{
	dst[0] = (unsigned char)(value & 0xFFU);
	dst[1] = (unsigned char)((value >> 8) & 0xFFU);
	dst[2] = (unsigned char)((value >> 16) & 0xFFU);
	dst[3] = (unsigned char)((value >> 24) & 0xFFU);
}

static uint32_t rotr32(uint32_t value, unsigned shift)
{
	return (value >> shift) | (value << (32U - shift));
}

static void blake2s_set_lastnode(RazeBlake2sState *state)
{
	state->f[1] = ~0U;
}

static void blake2s_set_lastblock(RazeBlake2sState *state)
{
	if (state->last_node) {
		blake2s_set_lastnode(state);
	}
	state->f[0] = ~0U;
}

static void blake2s_increment_counter(RazeBlake2sState *state, uint32_t inc)
{
	state->t[0] += inc;
	state->t[1] += (state->t[0] < inc);
}

#define G(r, i, m, a, b, c, d) \
	do { \
		a = a + b + m[blake2s_sigma[(r)][2U * (i) + 0U]]; \
		d = rotr32(d ^ a, 16U); \
		c = c + d; \
		b = rotr32(b ^ c, 12U); \
		a = a + b + m[blake2s_sigma[(r)][2U * (i) + 1U]]; \
		d = rotr32(d ^ a, 8U); \
		c = c + d; \
		b = rotr32(b ^ c, 7U); \
	} while (0)

static void blake2s_compress(
	RazeBlake2sState *state,
	const unsigned char block[BLAKE2S_BLOCKBYTES]
)
{
	uint32_t m[16];
	uint32_t v[16];
	unsigned r;
	size_t i;

	for (i = 0; i < 16U; ++i) {
		m[i] = load32(block + i * 4U);
	}

	for (i = 0; i < 8U; ++i) {
		v[i] = state->h[i];
	}
	v[8] = blake2s_iv[0];
	v[9] = blake2s_iv[1];
	v[10] = blake2s_iv[2];
	v[11] = blake2s_iv[3];
	v[12] = state->t[0] ^ blake2s_iv[4];
	v[13] = state->t[1] ^ blake2s_iv[5];
	v[14] = state->f[0] ^ blake2s_iv[6];
	v[15] = state->f[1] ^ blake2s_iv[7];

	for (r = 0; r < 10U; ++r) {
		G(r, 0, m, v[0], v[4], v[8], v[12]);
		G(r, 1, m, v[1], v[5], v[9], v[13]);
		G(r, 2, m, v[2], v[6], v[10], v[14]);
		G(r, 3, m, v[3], v[7], v[11], v[15]);
		G(r, 4, m, v[0], v[5], v[10], v[15]);
		G(r, 5, m, v[1], v[6], v[11], v[12]);
		G(r, 6, m, v[2], v[7], v[8], v[13]);
		G(r, 7, m, v[3], v[4], v[9], v[14]);
	}

	for (i = 0; i < 8U; ++i) {
		state->h[i] ^= v[i] ^ v[i + 8U];
	}
}

static void blake2s_init_param(
	RazeBlake2sState *state,
	uint32_t node_offset,
	uint32_t node_depth
)
{
	size_t i;

	memset(state, 0, sizeof(*state));
	for (i = 0; i < 8U; ++i) {
		state->h[i] = blake2s_iv[i];
	}

	state->h[0] ^= 0x02080020U;
	state->h[2] ^= node_offset;
	state->h[3] ^= (node_depth << 16U) | 0x20000000U;
}

static void blake2s_update(
	RazeBlake2sState *state,
	const unsigned char *input,
	size_t input_len
)
{
	while (input_len > 0U) {
		size_t left = state->buflen;
		size_t fill = sizeof(state->buf) - left;

		if (input_len > fill) {
			memcpy(state->buf + left, input, fill);
			state->buflen += fill;
			blake2s_increment_counter(state, BLAKE2S_BLOCKBYTES);
			blake2s_compress(state, state->buf);
			memcpy(state->buf, state->buf + BLAKE2S_BLOCKBYTES,
			       BLAKE2S_BLOCKBYTES);
			state->buflen -= BLAKE2S_BLOCKBYTES;
			input += fill;
			input_len -= fill;
		} else {
			memcpy(state->buf + left, input, input_len);
			state->buflen += input_len;
			return;
		}
	}
}

static void blake2s_final(
	RazeBlake2sState *state,
	unsigned char out_digest[BLAKE2S_OUTBYTES]
)
{
	size_t i;

	if (state->buflen > BLAKE2S_BLOCKBYTES) {
		blake2s_increment_counter(state, BLAKE2S_BLOCKBYTES);
		blake2s_compress(state, state->buf);
		state->buflen -= BLAKE2S_BLOCKBYTES;
		memcpy(state->buf, state->buf + BLAKE2S_BLOCKBYTES, state->buflen);
	}

	blake2s_increment_counter(state, (uint32_t)state->buflen);
	blake2s_set_lastblock(state);
	memset(state->buf + state->buflen, 0,
	       sizeof(state->buf) - state->buflen);
	blake2s_compress(state, state->buf);

	for (i = 0; i < 8U; ++i) {
		store32(out_digest + i * 4U, state->h[i]);
	}
}

void raze_blake2sp_init(RazeBlake2spState *state)
{
	unsigned i;

	if (state == 0) {
		return;
	}

	memset(state->buf, 0, sizeof(state->buf));
	state->buflen = 0U;
	blake2s_init_param(&state->root, 0U, 1U);

	for (i = 0; i < RAZE_BLAKE2SP_PARALLELISM_DEGREE; ++i) {
		blake2s_init_param(&state->leaves[i], i, 0U);
	}

	state->root.last_node = 1;
	state->leaves[RAZE_BLAKE2SP_PARALLELISM_DEGREE - 1U].last_node = 1;
}

void raze_blake2sp_update(
	RazeBlake2spState *state,
	const unsigned char *data,
	size_t data_len
)
{
	size_t left;
	size_t fill;
	unsigned i;

	if (state == 0 || (data == 0 && data_len != 0U)) {
		return;
	}

	left = state->buflen;
	fill = sizeof(state->buf) - left;

	if (left != 0U && data_len >= fill) {
		memcpy(state->buf + left, data, fill);
		for (i = 0; i < RAZE_BLAKE2SP_PARALLELISM_DEGREE; ++i) {
			blake2s_update(&state->leaves[i],
				state->buf + i * BLAKE2S_BLOCKBYTES,
				BLAKE2S_BLOCKBYTES);
		}
		data += fill;
		data_len -= fill;
		left = 0U;
	}

	while (data_len >=
	       RAZE_BLAKE2SP_PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES) {
		for (i = 0; i < RAZE_BLAKE2SP_PARALLELISM_DEGREE; ++i) {
			blake2s_update(&state->leaves[i],
				data + i * BLAKE2S_BLOCKBYTES,
				BLAKE2S_BLOCKBYTES);
		}
		data += RAZE_BLAKE2SP_PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES;
		data_len -= RAZE_BLAKE2SP_PARALLELISM_DEGREE * BLAKE2S_BLOCKBYTES;
	}

	if (data_len > 0U) {
		memcpy(state->buf + left, data, data_len);
		left += data_len;
	}
	state->buflen = left;
}

void raze_blake2sp_final(
	RazeBlake2spState *state,
	unsigned char out_digest[RAZE_BLAKE2SP_DIGEST_SIZE]
)
{
	unsigned char hash[RAZE_BLAKE2SP_PARALLELISM_DEGREE][BLAKE2S_OUTBYTES];
	unsigned i;

	if (state == 0 || out_digest == 0) {
		return;
	}

	for (i = 0; i < RAZE_BLAKE2SP_PARALLELISM_DEGREE; ++i) {
		if (state->buflen > i * BLAKE2S_BLOCKBYTES) {
			size_t left = state->buflen - i * BLAKE2S_BLOCKBYTES;
			if (left > BLAKE2S_BLOCKBYTES) {
				left = BLAKE2S_BLOCKBYTES;
			}
			blake2s_update(
				&state->leaves[i],
				state->buf + i * BLAKE2S_BLOCKBYTES,
				left
			);
		}
		blake2s_final(&state->leaves[i], hash[i]);
	}

	for (i = 0; i < RAZE_BLAKE2SP_PARALLELISM_DEGREE; ++i) {
		blake2s_update(&state->root, hash[i], BLAKE2S_OUTBYTES);
	}
	blake2s_final(&state->root, out_digest);
}

void raze_blake2sp_digest(
	const unsigned char *data,
	size_t data_len,
	unsigned char out_digest[RAZE_BLAKE2SP_DIGEST_SIZE]
)
{
	RazeBlake2spState state;

	raze_blake2sp_init(&state);
	raze_blake2sp_update(&state, data, data_len);
	raze_blake2sp_final(&state, out_digest);
}
