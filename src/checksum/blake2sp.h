#ifndef RAZE_CHECKSUM_BLAKE2SP_H
#define RAZE_CHECKSUM_BLAKE2SP_H

#include <stddef.h>
#include <stdint.h>

#define RAZE_BLAKE2SP_DIGEST_SIZE 32U
#define RAZE_BLAKE2SP_PARALLELISM_DEGREE 8U

typedef struct RazeBlake2sState {
	uint32_t h[8];
	uint32_t t[2];
	uint32_t f[2];
	unsigned char buf[2U * 64U];
	size_t buflen;
	int last_node;
} RazeBlake2sState;

typedef struct RazeBlake2spState {
	RazeBlake2sState leaves[RAZE_BLAKE2SP_PARALLELISM_DEGREE];
	RazeBlake2sState root;
	unsigned char buf[RAZE_BLAKE2SP_PARALLELISM_DEGREE * 64U];
	size_t buflen;
} RazeBlake2spState;

void raze_blake2sp_init(RazeBlake2spState *state);
void raze_blake2sp_update(
	RazeBlake2spState *state,
	const unsigned char *data,
	size_t data_len
);
void raze_blake2sp_final(
	RazeBlake2spState *state,
	unsigned char out_digest[RAZE_BLAKE2SP_DIGEST_SIZE]
);
void raze_blake2sp_digest(
	const unsigned char *data,
	size_t data_len,
	unsigned char out_digest[RAZE_BLAKE2SP_DIGEST_SIZE]
);

#endif
