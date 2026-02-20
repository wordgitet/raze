#ifndef RAZE_DECODE_RAR5_BIT_READER_H
#define RAZE_DECODE_RAR5_BIT_READER_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(__GNUC__) || defined(__clang__)
#define RAZE_RAR5_BR_FORCE_INLINE inline __attribute__((always_inline))
#else
#define RAZE_RAR5_BR_FORCE_INLINE inline
#endif

#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_UNDEFINED__)
#define RAZE_RAR5_BR_ENABLE_UNCHECKED 0
#else
#define RAZE_RAR5_BR_ENABLE_UNCHECKED 1
#endif

typedef struct RazeRar5BitReader {
	const unsigned char *data;
	size_t data_size;
	size_t byte_pos;
	unsigned int bit_pos;
	size_t fast16_end;
	size_t fast64_end;
} RazeRar5BitReader;

void raze_rar5_br_init(
	RazeRar5BitReader *reader,
	const unsigned char *data,
	size_t data_size
);

int raze_rar5_br_add_bits(RazeRar5BitReader *reader, unsigned int bits);
int raze_rar5_br_read_bits(
	RazeRar5BitReader *reader,
	unsigned int bits,
	uint64_t *value
);
uint16_t raze_rar5_br_peek16(const RazeRar5BitReader *reader);
int raze_rar5_br_align_byte(RazeRar5BitReader *reader);
size_t raze_rar5_br_bit_offset(const RazeRar5BitReader *reader);

static RAZE_RAR5_BR_FORCE_INLINE int raze_rar5_br_in_fast16(
	const RazeRar5BitReader *reader
)
{
#if !RAZE_RAR5_BR_ENABLE_UNCHECKED
	return 0;
#endif
	if (reader == 0 || reader->data == 0 || reader->bit_pos > 7U) {
		return 0;
	}
	if (reader->data_size < 3U) {
		return 0;
	}
	return reader->byte_pos <= reader->fast16_end;
}

static RAZE_RAR5_BR_FORCE_INLINE int raze_rar5_br_in_fast64(
	const RazeRar5BitReader *reader
)
{
#if !RAZE_RAR5_BR_ENABLE_UNCHECKED
	return 0;
#endif
	if (reader == 0 || reader->data == 0 || reader->bit_pos > 7U) {
		return 0;
	}
	if (reader->data_size < 8U) {
		return 0;
	}
	return reader->byte_pos <= reader->fast64_end;
}

static RAZE_RAR5_BR_FORCE_INLINE uint64_t raze_rar5_br_load_be64_unchecked(
	const unsigned char *ptr
)
{
	uint64_t raw;

	memcpy(&raw, ptr, sizeof(raw));
	return __builtin_bswap64(raw);
}

static RAZE_RAR5_BR_FORCE_INLINE uint16_t raze_rar5_br_peek16_fast_unchecked(
	const RazeRar5BitReader *reader
)
{
	const unsigned char *p = reader->data + reader->byte_pos;
	uint32_t bit_field;
	unsigned int shift;

	bit_field = ((uint32_t)p[0] << 16U) |
		    ((uint32_t)p[1] << 8U) |
		    (uint32_t)p[2];
	shift = 8U - reader->bit_pos;
	bit_field >>= shift;
	return (uint16_t)(bit_field & 0xffffU);
}

static RAZE_RAR5_BR_FORCE_INLINE uint32_t raze_rar5_br_getbits32_fast_unchecked(
	const RazeRar5BitReader *reader,
	unsigned int bits
)
{
	uint64_t chunk;

	if (bits == 0U) {
		return 0U;
	}

	chunk = raze_rar5_br_load_be64_unchecked(reader->data + reader->byte_pos);
	chunk <<= reader->bit_pos;
	return (uint32_t)(chunk >> (64U - bits));
}

static RAZE_RAR5_BR_FORCE_INLINE uint64_t raze_rar5_br_getbits64_fast_unchecked(
	const RazeRar5BitReader *reader,
	unsigned int bits
)
{
	uint64_t chunk;

	if (bits == 0U) {
		return 0U;
	}

	chunk = raze_rar5_br_load_be64_unchecked(reader->data + reader->byte_pos);
	chunk <<= reader->bit_pos;
	return chunk >> (64U - bits);
}

static RAZE_RAR5_BR_FORCE_INLINE void raze_rar5_br_addbits_fast_unchecked(
	RazeRar5BitReader *reader,
	unsigned int bits
)
{
	unsigned int next_bit_pos = reader->bit_pos + bits;

	reader->byte_pos += (size_t)(next_bit_pos >> 3U);
	reader->bit_pos = next_bit_pos & 7U;
}

#endif
