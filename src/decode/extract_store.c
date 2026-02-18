#include "extract_store.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include "../checksum/blake2sp.h"
#include "../checksum/crc32.h"
#include "../cli/overwrite_prompt.h"
#include "../crypto/rar5_crypt.h"
#include "../crypto/rar5_kdf.h"
#include "../format/rar5/block_reader.h"
#include "../format/rar5/file_header.h"
#include "../format/rar5/vint.h"
#include "../io/fs_meta.h"
#include "../io/path_guard.h"
#include "../io/volume_chain.h"
#include "decode_internal.h"
#include "extract_compressed.h"

#define RAZE_RAR5_HEAD_MAIN 1U
#define RAZE_RAR5_HEAD_FILE 2U
#define RAZE_RAR5_HEAD_SERVICE 3U
#define RAZE_RAR5_HEAD_CRYPT 4U
#define RAZE_RAR5_HEAD_ENDARC 5U

#define RAZE_RAR5_MHFL_VOLUME 0x0001U
#define RAZE_RAR5_MHFL_SOLID 0x0004U
#define RAZE_RAR5_CHFL_PSWCHECK 0x0001U
#define RAZE_RAR5_HFL_SPLITBEFORE 0x0008U
#define RAZE_RAR5_HFL_SPLITAFTER 0x0010U
#define RAZE_RAR5_HFL_EXTRA 0x0001U
#define RAZE_RAR5_HFL_DATA 0x0002U
#define RAZE_RAR5_MAX_HEADER_SIZE (2U * 1024U * 1024U)

typedef struct PendingDirMeta {
    char *path;
    int has_mode;
    mode_t mode;
    int has_mtime;
    time_t mtime;
} PendingDirMeta;

typedef struct PendingDirMetaList {
    PendingDirMeta *items;
    size_t count;
    size_t capacity;
} PendingDirMetaList;

typedef struct PendingSplitFile {
    int active;
    int hash_key_cached;
    RazeRar5FileHeader header;
    unsigned char hash_key[RAZE_RAR5_HASH_KEY_SIZE];
    unsigned char *packed_data;
    size_t packed_size;
    size_t packed_capacity;
} PendingSplitFile;

typedef struct HeaderCryptState {
    int enabled;
    unsigned char key[RAZE_RAR5_KEY_SIZE];
} HeaderCryptState;

typedef struct RazeEncProfileStats {
	int enabled;
	uint64_t header_kdf_ns;
	uint64_t header_decrypt_ns;
	uint64_t split_kdf_ns;
	uint64_t split_hash_verify_ns;
} RazeEncProfileStats;

static RazeEncProfileStats g_enc_profile;

static const char *header_type_name(uint64_t header_type)
{
	switch (header_type) {
	case RAZE_RAR5_HEAD_MAIN:
		return "HEAD_MAIN";
	case RAZE_RAR5_HEAD_FILE:
		return "HEAD_FILE";
	case RAZE_RAR5_HEAD_SERVICE:
		return "HEAD_SERVICE";
	case RAZE_RAR5_HEAD_CRYPT:
		return "HEAD_CRYPT";
	case RAZE_RAR5_HEAD_ENDARC:
		return "HEAD_ENDARC";
	default:
		return "HEAD_UNKNOWN";
	}
}

static int enc_profile_enabled(void)
{
	const char *value = getenv("RAZE_PROFILE_ENC");

	return value != 0 && value[0] == '1' && value[1] == '\0';
}

static uint64_t monotonic_ns(void)
{
	struct timespec ts;

#if defined(CLOCK_MONOTONIC)
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		return 0U;
	}
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#else
	if (timespec_get(&ts, TIME_UTC) != TIME_UTC) {
		return 0U;
	}
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

static void profile_add_elapsed(uint64_t *slot, uint64_t t0)
{
	uint64_t t1;

	if (slot == 0 || t0 == 0U) {
		return;
	}
	t1 = monotonic_ns();
	if (t1 > t0) {
		*slot += t1 - t0;
	}
}

static double ns_to_ms(uint64_t ns)
{
	return (double)ns / 1000000.0;
}

static void enc_profile_reset(void)
{
	memset(&g_enc_profile, 0, sizeof(g_enc_profile));
	g_enc_profile.enabled = enc_profile_enabled();
}

static void enc_profile_report(const char *archive_path)
{
	if (!g_enc_profile.enabled) {
		return;
	}

	printf("[raze-enc-prof] archive='%s' header_kdf=%.3fms "
	       "header_decrypt=%.3fms split_kdf=%.3fms split_hash_verify=%.3fms\n",
	       archive_path != 0 ? archive_path : "<unknown>",
	       ns_to_ms(g_enc_profile.header_kdf_ns),
	       ns_to_ms(g_enc_profile.header_decrypt_ns),
	       ns_to_ms(g_enc_profile.split_kdf_ns),
	       ns_to_ms(g_enc_profile.split_hash_verify_ns));
}

static int diag_is_empty(void)
{
	const char *detail = raze_last_error_detail();
	return detail == 0 || detail[0] == '\0';
}

static int skip_forward(FILE *file, uint64_t bytes) {
    while (bytes > 0) {
        long chunk;
        if (bytes > (uint64_t)LONG_MAX) {
            chunk = LONG_MAX;
        } else {
            chunk = (long)bytes;
        }
        if (fseek(file, chunk, SEEK_CUR) != 0) {
            return 0;
        }
        bytes -= (uint64_t)chunk;
    }
    return 1;
}

static uint32_t read_u32le(const unsigned char raw[4]) {
    return ((uint32_t)raw[0]) |
           ((uint32_t)raw[1] << 8) |
           ((uint32_t)raw[2] << 16) |
           ((uint32_t)raw[3] << 24);
}

static void secure_zero(void *ptr, size_t len)
{
	volatile unsigned char *p = (volatile unsigned char *)ptr;
	while (len-- > 0U) {
		*p++ = 0U;
	}
}

static void header_crypt_reset(HeaderCryptState *state) {
    if (state == 0) {
        return;
    }
    memset(state, 0, sizeof(*state));
}

static int read_exact(FILE *file, unsigned char *buf, size_t len) {
    size_t nread;

    if (len == 0U) {
        return 1;
    }
    nread = fread(buf, 1, len, file);
    return nread == len;
}

static int current_file_offset(FILE *file, uint64_t *offset) {
    long pos;

    if (file == 0 || offset == 0) {
        return 0;
    }

    pos = ftell(file);
    if (pos < 0) {
        return 0;
    }

    *offset = (uint64_t)(unsigned long)pos;
    return 1;
}

static RazeStatus parse_head_crypt(
    const RazeRar5BlockHeader *block,
    const unsigned char *buf,
    size_t buf_len,
    const RazeExtractOptions *options,
    HeaderCryptState *state
) {
    size_t cursor;
    size_t consumed = 0;
    uint64_t crypt_version = 0;
    uint64_t enc_flags = 0;
    uint8_t lg2_count;
    unsigned char salt[RAZE_RAR5_SALT_SIZE];
    unsigned char psw_check[RAZE_RAR5_PSWCHECK_SIZE];
    unsigned char psw_check_csum[RAZE_RAR5_PSWCHECK_CSUM_SIZE];
    unsigned char hash_key[RAZE_RAR5_HASH_KEY_SIZE];
    unsigned char psw_value[RAZE_RAR5_KEY_SIZE];
    int use_psw_check;
    int psw_check_valid = 0;
    int has_password;
    RazeStatus status = RAZE_STATUS_OK;

    if (block == 0 || buf == 0 || options == 0 || state == 0) {
        raze_diag_set("internal bad arguments while parsing HEAD_CRYPT");
        return RAZE_STATUS_BAD_ARGUMENT;
    }
    if (block->body_offset > buf_len || block->extra_offset > buf_len || block->body_offset > block->extra_offset) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }

    memset(salt, 0, sizeof(salt));
    memset(psw_check, 0, sizeof(psw_check));
    memset(psw_check_csum, 0, sizeof(psw_check_csum));
    memset(hash_key, 0, sizeof(hash_key));
    memset(psw_value, 0, sizeof(psw_value));

    cursor = block->body_offset;
    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &crypt_version)) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }
    cursor += consumed;
    if (!raze_vint_decode(buf + cursor, block->extra_offset - cursor, &consumed, &enc_flags)) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }
    cursor += consumed;
    if (crypt_version != 0U) {
        raze_diag_set("unsupported HEAD_CRYPT version: %llu",
                      (unsigned long long)crypt_version);
        return RAZE_STATUS_UNSUPPORTED_FEATURE;
    }
    if (block->extra_offset - cursor < 1U + RAZE_RAR5_SALT_SIZE) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }

    lg2_count = buf[cursor++];
    if (lg2_count > RAZE_RAR5_KDF_LG2_MAX) {
        raze_diag_set("unsupported KDF iteration exponent in HEAD_CRYPT: %u",
                      (unsigned)lg2_count);
        return RAZE_STATUS_UNSUPPORTED_FEATURE;
    }
    memcpy(salt, buf + cursor, RAZE_RAR5_SALT_SIZE);
    cursor += RAZE_RAR5_SALT_SIZE;

    use_psw_check = (enc_flags & RAZE_RAR5_CHFL_PSWCHECK) != 0U;
    if (use_psw_check) {
        if (block->extra_offset - cursor < RAZE_RAR5_PSWCHECK_SIZE + RAZE_RAR5_PSWCHECK_CSUM_SIZE) {
            return RAZE_STATUS_BAD_ARCHIVE;
        }
        memcpy(psw_check, buf + cursor, RAZE_RAR5_PSWCHECK_SIZE);
        cursor += RAZE_RAR5_PSWCHECK_SIZE;
        memcpy(psw_check_csum, buf + cursor, RAZE_RAR5_PSWCHECK_CSUM_SIZE);
        cursor += RAZE_RAR5_PSWCHECK_CSUM_SIZE;
        psw_check_valid = raze_rar5_pswcheck_validate(psw_check, psw_check_csum);
    }

	has_password = options->password_present && options->password != 0 && options->password[0] != '\0';
	if (!has_password) {
		raze_diag_set("password is required for encrypted archive headers");
		return RAZE_STATUS_BAD_ARGUMENT;
	}

	{
		uint64_t kdf_t0 = 0U;
		if (g_enc_profile.enabled) {
			kdf_t0 = monotonic_ns();
		}
		if (!raze_rar5_kdf_derive(
				options->password,
				salt,
				lg2_count,
				state->key,
				hash_key,
				psw_value
			)) {
			profile_add_elapsed(&g_enc_profile.header_kdf_ns, kdf_t0);
			status = RAZE_STATUS_UNSUPPORTED_FEATURE;
			raze_diag_set("unable to derive header decryption key");
			goto done;
		}
		profile_add_elapsed(&g_enc_profile.header_kdf_ns, kdf_t0);
	}

    if (use_psw_check && psw_check_valid) {
        unsigned char calc_check[RAZE_RAR5_PSWCHECK_SIZE];
        unsigned char calc_check_csum[RAZE_RAR5_PSWCHECK_CSUM_SIZE];

        if (!raze_rar5_pswcheck_from_value(psw_value, calc_check, calc_check_csum)) {
            status = RAZE_STATUS_UNSUPPORTED_FEATURE;
            raze_diag_set("unable to verify HEAD_CRYPT password check data");
            goto done;
        }
        if (memcmp(calc_check, psw_check, RAZE_RAR5_PSWCHECK_SIZE) != 0) {
            status = RAZE_STATUS_CRC_MISMATCH;
            raze_diag_set("incorrect password for encrypted archive headers");
            goto done;
        }
    }

    state->enabled = 1;

done:
    memset(salt, 0, sizeof(salt));
    memset(psw_check, 0, sizeof(psw_check));
    memset(psw_check_csum, 0, sizeof(psw_check_csum));
    memset(hash_key, 0, sizeof(hash_key));
    memset(psw_value, 0, sizeof(psw_value));
    return status;
}

static RazeRar5ReadResult read_encrypted_header_block(
    FILE *file,
    const HeaderCryptState *crypt,
    RazeRar5BlockHeader *block,
    unsigned char **header_buf,
    size_t *header_buf_len,
    RazeStatus *error_status
) {
    unsigned char iv[RAZE_RAR5_INITV_SIZE];
    unsigned char first_cipher[16];
    unsigned char first_plain[16];
    unsigned char *cipher = 0;
    unsigned char *plain = 0;
    uint64_t header_offset = 0;
    uint64_t header_size_u64 = 0;
    uint64_t header_type = 0;
    uint64_t flags = 0;
    uint64_t extra_size = 0;
    uint64_t data_size = 0;
    size_t size_raw_len = 0;
    size_t consumed = 0;
    size_t cursor = 0;
    size_t total_plain_len;
    size_t enc_len;
    uint32_t crc_expected;
    uint32_t crc_calc;
    uint32_t crc_init;
    unsigned char *buf = 0;

    if (error_status != 0) {
        *error_status = RAZE_STATUS_ERROR;
    }

    if (file == 0 || crypt == 0 || !crypt->enabled || block == 0 || header_buf == 0 || header_buf_len == 0 ||
        error_status == 0) {
        if (error_status != 0) {
            *error_status = RAZE_STATUS_BAD_ARGUMENT;
        }
        return RAZE_RAR5_READ_ERROR;
    }

    *header_buf = 0;
    *header_buf_len = 0;
    memset(block, 0, sizeof(*block));

    if (!current_file_offset(file, &header_offset)) {
        *error_status = RAZE_STATUS_IO;
        return RAZE_RAR5_READ_ERROR;
    }
    if (feof(file)) {
        return RAZE_RAR5_READ_EOF;
    }

    if (!read_exact(file, iv, sizeof(iv))) {
        if (feof(file)) {
            return RAZE_RAR5_READ_EOF;
        }
        *error_status = RAZE_STATUS_IO;
        return RAZE_RAR5_READ_ERROR;
    }
    if (!read_exact(file, first_cipher, sizeof(first_cipher))) {
        *error_status = RAZE_STATUS_BAD_ARCHIVE;
        return RAZE_RAR5_READ_ERROR;
    }
    {
	uint64_t dec_t0 = 0U;
	if (g_enc_profile.enabled) {
		dec_t0 = monotonic_ns();
	}
    if (!raze_rar5_aes256_cbc_decrypt(crypt->key, iv, first_cipher, sizeof(first_cipher), first_plain)) {
        profile_add_elapsed(&g_enc_profile.header_decrypt_ns, dec_t0);
        *error_status = RAZE_STATUS_CRC_MISMATCH;
        return RAZE_RAR5_READ_ERROR;
    }
    profile_add_elapsed(&g_enc_profile.header_decrypt_ns, dec_t0);
    }

    if (!raze_vint_decode(first_plain + 4U, sizeof(first_plain) - 4U, &consumed, &header_size_u64)) {
        *error_status = RAZE_STATUS_CRC_MISMATCH;
        return RAZE_RAR5_READ_ERROR;
    }
    size_raw_len = consumed;
    if (header_size_u64 == 0U || header_size_u64 > RAZE_RAR5_MAX_HEADER_SIZE) {
        *error_status = RAZE_STATUS_CRC_MISMATCH;
        return RAZE_RAR5_READ_ERROR;
    }

    total_plain_len = 4U + size_raw_len + (size_t)header_size_u64;
    enc_len = (total_plain_len + 15U) & ~((size_t)15U);
    if (enc_len < 16U || enc_len > RAZE_RAR5_MAX_HEADER_SIZE + 32U) {
        *error_status = RAZE_STATUS_CRC_MISMATCH;
        return RAZE_RAR5_READ_ERROR;
    }

    cipher = (unsigned char *)malloc(enc_len);
    plain = (unsigned char *)malloc(enc_len);
    if (cipher == 0 || plain == 0) {
        free(cipher);
        free(plain);
        *error_status = RAZE_STATUS_IO;
        return RAZE_RAR5_READ_ERROR;
    }

    memcpy(cipher, first_cipher, sizeof(first_cipher));
    if (enc_len > sizeof(first_cipher) && !read_exact(file, cipher + sizeof(first_cipher), enc_len - sizeof(first_cipher))) {
        free(cipher);
        free(plain);
        *error_status = RAZE_STATUS_BAD_ARCHIVE;
        return RAZE_RAR5_READ_ERROR;
    }

    {
	uint64_t dec_t0 = 0U;
	if (g_enc_profile.enabled) {
		dec_t0 = monotonic_ns();
	}
    if (!raze_rar5_aes256_cbc_decrypt(crypt->key, iv, cipher, enc_len, plain)) {
        profile_add_elapsed(&g_enc_profile.header_decrypt_ns, dec_t0);
        free(cipher);
        free(plain);
        *error_status = RAZE_STATUS_CRC_MISMATCH;
        return RAZE_RAR5_READ_ERROR;
    }
    profile_add_elapsed(&g_enc_profile.header_decrypt_ns, dec_t0);
    }

    crc_expected = read_u32le(plain);
    crc_init = raze_crc32_init();
    crc_init = raze_crc32_update(crc_init, plain + 4U, size_raw_len);
    crc_init = raze_crc32_update(crc_init, plain + 4U + size_raw_len, (size_t)header_size_u64);
    crc_calc = raze_crc32_final(crc_init);

    buf = (unsigned char *)malloc((size_t)header_size_u64);
    if (buf == 0) {
        free(cipher);
        free(plain);
        *error_status = RAZE_STATUS_IO;
        return RAZE_RAR5_READ_ERROR;
    }
    memcpy(buf, plain + 4U + size_raw_len, (size_t)header_size_u64);

    if (!raze_vint_decode(buf + cursor, (size_t)header_size_u64 - cursor, &consumed, &header_type)) {
        free(cipher);
        free(plain);
        free(buf);
        *error_status = RAZE_STATUS_CRC_MISMATCH;
        return RAZE_RAR5_READ_ERROR;
    }
    cursor += consumed;

    if (!raze_vint_decode(buf + cursor, (size_t)header_size_u64 - cursor, &consumed, &flags)) {
        free(cipher);
        free(plain);
        free(buf);
        *error_status = RAZE_STATUS_CRC_MISMATCH;
        return RAZE_RAR5_READ_ERROR;
    }
    cursor += consumed;

    if ((flags & RAZE_RAR5_HFL_EXTRA) != 0U) {
        if (!raze_vint_decode(buf + cursor, (size_t)header_size_u64 - cursor, &consumed, &extra_size)) {
            free(cipher);
            free(plain);
            free(buf);
            *error_status = RAZE_STATUS_CRC_MISMATCH;
            return RAZE_RAR5_READ_ERROR;
        }
        cursor += consumed;
        if (extra_size > header_size_u64) {
            free(cipher);
            free(plain);
            free(buf);
            *error_status = RAZE_STATUS_CRC_MISMATCH;
            return RAZE_RAR5_READ_ERROR;
        }
    }

    if ((flags & RAZE_RAR5_HFL_DATA) != 0U) {
        if (!raze_vint_decode(buf + cursor, (size_t)header_size_u64 - cursor, &consumed, &data_size)) {
            free(cipher);
            free(plain);
            free(buf);
            *error_status = RAZE_STATUS_CRC_MISMATCH;
            return RAZE_RAR5_READ_ERROR;
        }
        cursor += consumed;
    }

    block->header_offset = header_offset;
    block->data_offset = header_offset + RAZE_RAR5_INITV_SIZE + (uint64_t)enc_len;
    block->next_offset = block->data_offset + data_size;
    block->header_type = header_type;
    block->flags = flags;
    block->header_size = header_size_u64;
    block->data_size = data_size;
    block->extra_size = extra_size;
    block->header_crc = crc_expected;
    block->crc_ok = crc_expected == crc_calc;
    block->body_offset = cursor;
    block->extra_offset = (size_t)(header_size_u64 - extra_size);

    free(cipher);
    free(plain);
    *header_buf = buf;
    *header_buf_len = (size_t)header_size_u64;

    if (!block->crc_ok) {
        *error_status = RAZE_STATUS_CRC_MISMATCH;
        return RAZE_RAR5_READ_ERROR;
    }
    *error_status = RAZE_STATUS_OK;
    return RAZE_RAR5_READ_OK;
}

static RazeRar5ReadResult read_block_with_header_crypt(
    FILE *file,
    const HeaderCryptState *crypt,
    RazeRar5BlockHeader *block,
    unsigned char **header_buf,
    size_t *header_buf_len,
    RazeStatus *error_status
) {
    if (crypt != 0 && crypt->enabled) {
        return read_encrypted_header_block(file, crypt, block, header_buf, header_buf_len, error_status);
    }
    return raze_rar5_read_block(file, block, header_buf, header_buf_len, error_status);
}

static void pending_dir_meta_list_free(PendingDirMetaList *list) {
    size_t i;

    if (list == 0) {
        return;
    }

    for (i = 0; i < list->count; ++i) {
        free(list->items[i].path);
    }
    free(list->items);
    list->items = 0;
    list->count = 0;
    list->capacity = 0;
}

static RazeStatus pending_dir_meta_list_add(
    PendingDirMetaList *list,
    const char *path,
    int has_mode,
    mode_t mode,
    int has_mtime,
    time_t mtime
) {
    PendingDirMeta *expanded;
    size_t path_len;

    if (list == 0 || path == 0) {
        return RAZE_STATUS_BAD_ARGUMENT;
    }

    if (list->count == list->capacity) {
        size_t new_capacity = list->capacity == 0 ? 8U : list->capacity * 2U;
        expanded = (PendingDirMeta *)realloc(list->items, new_capacity * sizeof(*expanded));
        if (expanded == 0) {
            return RAZE_STATUS_IO;
        }
        list->items = expanded;
        list->capacity = new_capacity;
    }

    path_len = strlen(path) + 1U;
    list->items[list->count].path = (char *)malloc(path_len);
    if (list->items[list->count].path == 0) {
        return RAZE_STATUS_IO;
    }
    memcpy(list->items[list->count].path, path, path_len);
    list->items[list->count].has_mode = has_mode;
    list->items[list->count].mode = mode;
    list->items[list->count].has_mtime = has_mtime;
    list->items[list->count].mtime = mtime;
    list->count += 1;

    return RAZE_STATUS_OK;
}

static void pending_split_file_reset(PendingSplitFile *pending) {
    if (pending == 0) {
        return;
    }

    raze_rar5_file_header_free(&pending->header);
    secure_zero(pending->hash_key, sizeof(pending->hash_key));
    pending->active = 0;
    pending->hash_key_cached = 0;
    pending->packed_size = 0;
}

static void pending_split_file_free(PendingSplitFile *pending) {
    if (pending == 0) {
        return;
    }

    pending_split_file_reset(pending);
    free(pending->packed_data);
    pending->packed_data = 0;
    pending->packed_capacity = 0;
}

static int file_header_clone(const RazeRar5FileHeader *src, RazeRar5FileHeader *dst) {
    size_t name_len;

    if (src == 0 || dst == 0 || src->name == 0) {
        return 0;
    }

    memset(dst, 0, sizeof(*dst));
    *dst = *src;
    dst->name = 0;
    dst->name_len = 0;

    name_len = src->name_len + 1U;
    dst->name = (char *)malloc(name_len);
    if (dst->name == 0) {
        memset(dst, 0, sizeof(*dst));
        return 0;
    }

    memcpy(dst->name, src->name, name_len);
    dst->name_len = src->name_len;
    return 1;
}

static int pending_split_ensure_capacity(PendingSplitFile *pending, size_t need) {
    unsigned char *expanded;
    size_t cap;

    if (pending == 0) {
        return 0;
    }
    if (pending->packed_capacity >= need) {
        return 1;
    }

    cap = pending->packed_capacity == 0U ? 65536U : pending->packed_capacity;
    while (cap < need) {
        if (cap > SIZE_MAX / 2U) {
            return 0;
        }
        cap *= 2U;
    }

    expanded = (unsigned char *)realloc(pending->packed_data, cap);
    if (expanded == 0) {
        return 0;
    }

    pending->packed_data = expanded;
    pending->packed_capacity = cap;
    return 1;
}

static RazeStatus pending_split_append_data(
    PendingSplitFile *pending,
    FILE *archive,
    uint64_t bytes,
    const RazeRar5FileHeader *part_header,
    const RazeExtractOptions *options
) {
    unsigned char chunk[1U << 16];
    int verify_hash;
    int use_hash_key = 0;
    RazeBlake2spState blake_state;
    unsigned char actual_hash[RAZE_BLAKE2SP_DIGEST_SIZE];
    unsigned char mac_hash[RAZE_BLAKE2SP_DIGEST_SIZE];
    const unsigned char *compare_hash = actual_hash;
    unsigned char key[RAZE_RAR5_KEY_SIZE];
    unsigned char hash_key[RAZE_RAR5_HASH_KEY_SIZE];
    unsigned char psw_value[RAZE_RAR5_KEY_SIZE];
    unsigned char calc_psw_check[RAZE_RAR5_PSWCHECK_SIZE];
    unsigned char calc_psw_check_csum[RAZE_RAR5_PSWCHECK_CSUM_SIZE];

    if (pending == 0 || archive == 0 || part_header == 0) {
        return RAZE_STATUS_BAD_ARGUMENT;
    }
    if (!pending->active) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }

    memset(actual_hash, 0, sizeof(actual_hash));
    memset(mac_hash, 0, sizeof(mac_hash));
    memset(key, 0, sizeof(key));
    memset(hash_key, 0, sizeof(hash_key));
    memset(psw_value, 0, sizeof(psw_value));
    memset(calc_psw_check, 0, sizeof(calc_psw_check));
    memset(calc_psw_check_csum, 0, sizeof(calc_psw_check_csum));

    verify_hash = part_header->hash_present && part_header->hash_is_packed_part;
    if (verify_hash) {
        if (part_header->hash_type != RAZE_RAR5_HASH_TYPE_BLAKE2SP) {
            return RAZE_STATUS_UNSUPPORTED_FEATURE;
        }
		raze_blake2sp_init(&blake_state);
		if (part_header->crypt_use_hash_key) {
			if (options == 0 || !options->password_present ||
			    options->password == 0 || options->password[0] == '\0') {
				return RAZE_STATUS_BAD_ARGUMENT;
			}
			if (pending->hash_key_cached) {
				memcpy(hash_key, pending->hash_key, sizeof(hash_key));
			} else {
				{
					uint64_t kdf_t0 = 0U;
					if (g_enc_profile.enabled) {
						kdf_t0 = monotonic_ns();
					}
					if (!raze_rar5_kdf_derive(
							options->password,
							part_header->crypt_salt,
							part_header->crypt_lg2_count,
							key,
							hash_key,
							psw_value
						)) {
						profile_add_elapsed(&g_enc_profile.split_kdf_ns, kdf_t0);
						secure_zero(key, sizeof(key));
						secure_zero(hash_key, sizeof(hash_key));
						secure_zero(psw_value, sizeof(psw_value));
						return RAZE_STATUS_UNSUPPORTED_FEATURE;
					}
					profile_add_elapsed(&g_enc_profile.split_kdf_ns, kdf_t0);
				}
				if (part_header->crypt_use_psw_check &&
				    raze_rar5_pswcheck_validate(
					part_header->crypt_psw_check,
					part_header->crypt_psw_check_csum
				    )) {
					if (!raze_rar5_pswcheck_from_value(
							psw_value,
							calc_psw_check,
							calc_psw_check_csum
						)) {
						secure_zero(key, sizeof(key));
						secure_zero(hash_key, sizeof(hash_key));
						secure_zero(psw_value, sizeof(psw_value));
						secure_zero(calc_psw_check, sizeof(calc_psw_check));
						secure_zero(calc_psw_check_csum, sizeof(calc_psw_check_csum));
						return RAZE_STATUS_UNSUPPORTED_FEATURE;
					}
					if (memcmp(calc_psw_check, part_header->crypt_psw_check,
						   RAZE_RAR5_PSWCHECK_SIZE) != 0) {
						secure_zero(key, sizeof(key));
						secure_zero(hash_key, sizeof(hash_key));
						secure_zero(psw_value, sizeof(psw_value));
						secure_zero(calc_psw_check, sizeof(calc_psw_check));
						secure_zero(calc_psw_check_csum, sizeof(calc_psw_check_csum));
						return RAZE_STATUS_CRC_MISMATCH;
					}
				}
				memcpy(pending->hash_key, hash_key, sizeof(hash_key));
				pending->hash_key_cached = 1;
			}
			use_hash_key = 1;
		}
	}

    while (bytes > 0) {
        size_t want = sizeof(chunk);
        size_t nread;

        if (bytes < want) {
            want = (size_t)bytes;
        }

        nread = fread(chunk, 1, want, archive);
        if (nread == 0) {
            secure_zero(key, sizeof(key));
            secure_zero(hash_key, sizeof(hash_key));
            secure_zero(psw_value, sizeof(psw_value));
            secure_zero(calc_psw_check, sizeof(calc_psw_check));
            secure_zero(calc_psw_check_csum, sizeof(calc_psw_check_csum));
            if (feof(archive)) {
                return RAZE_STATUS_IO;
            }
            return RAZE_STATUS_IO;
        }

        if (verify_hash) {
		uint64_t hash_t0 = 0U;
		if (g_enc_profile.enabled) {
			hash_t0 = monotonic_ns();
		}
            raze_blake2sp_update(&blake_state, chunk, nread);
		profile_add_elapsed(&g_enc_profile.split_hash_verify_ns, hash_t0);
        }

        if (pending->packed_size > SIZE_MAX - nread) {
            secure_zero(key, sizeof(key));
            secure_zero(hash_key, sizeof(hash_key));
            secure_zero(psw_value, sizeof(psw_value));
            secure_zero(calc_psw_check, sizeof(calc_psw_check));
            secure_zero(calc_psw_check_csum, sizeof(calc_psw_check_csum));
            return RAZE_STATUS_UNSUPPORTED_FEATURE;
        }
        if (!pending_split_ensure_capacity(pending, pending->packed_size + nread)) {
            secure_zero(key, sizeof(key));
            secure_zero(hash_key, sizeof(hash_key));
            secure_zero(psw_value, sizeof(psw_value));
            secure_zero(calc_psw_check, sizeof(calc_psw_check));
            secure_zero(calc_psw_check_csum, sizeof(calc_psw_check_csum));
            return RAZE_STATUS_IO;
        }
        memcpy(pending->packed_data + pending->packed_size, chunk, nread);
        pending->packed_size += nread;
        bytes -= (uint64_t)nread;
    }

    if (verify_hash) {
	uint64_t hash_t0 = 0U;
	if (g_enc_profile.enabled) {
		hash_t0 = monotonic_ns();
	}
        raze_blake2sp_final(&blake_state, actual_hash);
        if (use_hash_key) {
            if (!raze_rar5_digest_to_mac(actual_hash, hash_key, mac_hash)) {
		profile_add_elapsed(&g_enc_profile.split_hash_verify_ns, hash_t0);
                secure_zero(key, sizeof(key));
                secure_zero(hash_key, sizeof(hash_key));
                secure_zero(psw_value, sizeof(psw_value));
                secure_zero(calc_psw_check, sizeof(calc_psw_check));
                secure_zero(calc_psw_check_csum, sizeof(calc_psw_check_csum));
                return RAZE_STATUS_UNSUPPORTED_FEATURE;
            }
            compare_hash = mac_hash;
        }
        if (memcmp(compare_hash, part_header->hash_value, RAZE_BLAKE2SP_DIGEST_SIZE) != 0) {
		profile_add_elapsed(&g_enc_profile.split_hash_verify_ns, hash_t0);
            secure_zero(key, sizeof(key));
            secure_zero(hash_key, sizeof(hash_key));
            secure_zero(psw_value, sizeof(psw_value));
            secure_zero(calc_psw_check, sizeof(calc_psw_check));
            secure_zero(calc_psw_check_csum, sizeof(calc_psw_check_csum));
            return RAZE_STATUS_CRC_MISMATCH;
        }
	profile_add_elapsed(&g_enc_profile.split_hash_verify_ns, hash_t0);
    }

    secure_zero(key, sizeof(key));
    secure_zero(hash_key, sizeof(hash_key));
    secure_zero(psw_value, sizeof(psw_value));
    secure_zero(calc_psw_check, sizeof(calc_psw_check));
    secure_zero(calc_psw_check_csum, sizeof(calc_psw_check_csum));
    pending->header.pack_size = pending->packed_size;
    return RAZE_STATUS_OK;
}

static int pending_split_headers_compatible(
    const PendingSplitFile *pending,
    const RazeRar5FileHeader *part
) {
    if (pending == 0 || part == 0 || pending->header.name == 0 || part->name == 0) {
        return 0;
    }
    if (strcmp(pending->header.name, part->name) != 0) {
        return 0;
    }
    if (pending->header.method != part->method ||
        pending->header.comp_version != part->comp_version ||
        pending->header.comp_is_v50_compat != part->comp_is_v50_compat ||
        pending->header.dict_size_bytes != part->dict_size_bytes) {
        return 0;
    }
    if (pending->header.unp_size != part->unp_size) {
        return 0;
    }
    if (pending->header.is_dir != part->is_dir) {
        return 0;
    }
    if (pending->header.encrypted != part->encrypted ||
        pending->header.crypt_version != part->crypt_version ||
        pending->header.crypt_lg2_count != part->crypt_lg2_count) {
        return 0;
    }
    if (memcmp(pending->header.crypt_salt, part->crypt_salt, sizeof(part->crypt_salt)) != 0) {
        return 0;
    }
    return 1;
}

static void apply_entry_metadata(const RazeRar5FileHeader *fh, const char *path, int quiet) {
    mode_t mode;

    if (fh == 0 || path == 0) {
        return;
    }

    if (raze_fs_compute_mode(fh->host_os, fh->file_attr, fh->is_dir, &mode)) {
        raze_fs_apply_mode(path, mode, quiet);
    }

    if (fh->mtime_present) {
        raze_fs_apply_mtime(path, (time_t)fh->unix_mtime, quiet);
    }
}

static void apply_pending_dir_metadata(const PendingDirMetaList *list, int quiet) {
    size_t i;

    if (list == 0) {
        return;
    }

    for (i = 0; i < list->count; ++i) {
        const PendingDirMeta *item = &list->items[i];

        if (item->has_mode) {
            raze_fs_apply_mode(item->path, item->mode, quiet);
        }
        if (item->has_mtime) {
            raze_fs_apply_mtime(item->path, item->mtime, quiet);
        }
    }
}

static RazeStatus ensure_supported_file(const RazeRar5FileHeader *fh, int allow_split) {
    if (fh == 0) {
        return RAZE_STATUS_BAD_ARGUMENT;
    }
    if (!allow_split && (fh->split_before || fh->split_after)) {
        return RAZE_STATUS_UNSUPPORTED_FEATURE;
    }
    if ((fh->file_flags & RAZE_RAR5_FHFL_UNPUNKNOWN) != 0) {
        return RAZE_STATUS_UNSUPPORTED_FEATURE;
    }
    if (fh->method > 5) {
        return RAZE_STATUS_UNSUPPORTED_FEATURE;
    }
    if (fh->comp_version > 1) {
        return RAZE_STATUS_UNSUPPORTED_FEATURE;
    }
    if (fh->host_os != RAZE_RAR5_HOST_OS_WINDOWS &&
        fh->host_os != RAZE_RAR5_HOST_OS_UNIX) {
        return RAZE_STATUS_UNSUPPORTED_FEATURE;
    }
    if (fh->encrypted && fh->crypt_version != 0U) {
        return RAZE_STATUS_UNSUPPORTED_FEATURE;
    }
    if (fh->encrypted && fh->crypt_lg2_count > RAZE_RAR5_KDF_LG2_MAX) {
        return RAZE_STATUS_UNSUPPORTED_FEATURE;
    }
    if (!fh->encrypted && !fh->is_dir && fh->method == 0 && fh->pack_size != fh->unp_size) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }
    if (fh->method != 0 && fh->dict_size_bytes == 0) {
        return RAZE_STATUS_BAD_ARCHIVE;
    }
    return RAZE_STATUS_OK;
}

static RazeStatus copy_store_payload(
    FILE *archive,
    FILE *output,
    uint64_t size,
    int crc32_present,
    uint32_t expected_crc32,
    int hash_present,
    uint8_t hash_type,
    const unsigned char expected_hash[RAZE_BLAKE2SP_DIGEST_SIZE],
    int use_hash_key,
    const unsigned char *hash_key
) {
    unsigned char buf[1U << 16];
    uint64_t remaining = size;
    uint32_t crc = raze_crc32_init();
    RazeBlake2spState blake_state;
    unsigned char actual_hash[RAZE_BLAKE2SP_DIGEST_SIZE];
    unsigned char mac_hash[RAZE_BLAKE2SP_DIGEST_SIZE];
    const unsigned char *compare_hash = actual_hash;

    memset(actual_hash, 0, sizeof(actual_hash));
    memset(mac_hash, 0, sizeof(mac_hash));
    if (hash_present) {
        if (hash_type != RAZE_RAR5_HASH_TYPE_BLAKE2SP) {
            return RAZE_STATUS_UNSUPPORTED_FEATURE;
        }
        raze_blake2sp_init(&blake_state);
    }

    while (remaining > 0) {
        size_t want = sizeof(buf);
        size_t nread;
        size_t nwritten;

        if (remaining < want) {
            want = (size_t)remaining;
        }

        nread = fread(buf, 1, want, archive);
        if (nread == 0) {
            if (feof(archive)) {
                return RAZE_STATUS_BAD_ARCHIVE;
            }
            return RAZE_STATUS_IO;
        }

        if (output != 0) {
            nwritten = fwrite(buf, 1, nread, output);
            if (nwritten != nread) {
                return RAZE_STATUS_IO;
            }
        }

        crc = raze_crc32_update(crc, buf, nread);
        if (hash_present) {
            raze_blake2sp_update(&blake_state, buf, nread);
        }
        remaining -= (uint64_t)nread;
    }

    if (crc32_present) {
        uint32_t actual = raze_crc32_final(crc);
        if (actual != expected_crc32) {
            return RAZE_STATUS_CRC_MISMATCH;
        }
    }
    if (hash_present) {
        raze_blake2sp_final(&blake_state, actual_hash);
        if (use_hash_key) {
            if (!raze_rar5_digest_to_mac(actual_hash, hash_key, mac_hash)) {
                return RAZE_STATUS_UNSUPPORTED_FEATURE;
            }
            compare_hash = mac_hash;
        }
        if (memcmp(compare_hash, expected_hash, RAZE_BLAKE2SP_DIGEST_SIZE) != 0) {
            return RAZE_STATUS_CRC_MISMATCH;
        }
    }

    return RAZE_STATUS_OK;
}

static RazeStatus decode_payload(
	FILE *archive,
	FILE *output,
	const RazeRar5FileHeader *fh,
	RazeCompressedScratch *scratch,
	int solid_stream,
	const char *password,
	int password_present
)
{
	if (archive == 0 || fh == 0) {
		raze_diag_set("internal bad arguments while decoding payload");
		return RAZE_STATUS_BAD_ARGUMENT;
	}
	if (fh->encrypted &&
	    (!password_present || password == 0 || password[0] == '\0')) {
		raze_diag_set("password is required to extract encrypted entry '%s'",
			      fh->name != 0 ? fh->name : "<unknown>");
		return RAZE_STATUS_BAD_ARGUMENT;
	}

	if (fh->method == 0 && !fh->encrypted) {
		return copy_store_payload(
			archive,
			output,
			fh->pack_size,
			fh->crc32_present,
			fh->crc32,
			fh->hash_present,
			fh->hash_type,
			fh->hash_value,
			0,
			0
		);
	}

	return raze_extract_compressed_payload(
		archive,
		output,
		fh,
		scratch,
		solid_stream,
		password,
		password_present
	);
}

static RazeStatus extract_file_entry(
    FILE *payload_stream,
    uint64_t payload_size,
    const RazeRar5FileHeader *fh,
    const char *output_dir,
    const RazeExtractOptions *options,
    int archive_is_solid,
    RazeOverwritePrompt *prompt,
    PendingDirMetaList *pending_dirs,
    RazeCompressedScratch *scratch
) {
    struct stat st;
    char out_path[4096];
    FILE *output = 0;
    RazeStatus status;
    int remove_output = 0;
    int solid_stream;

    if (payload_stream == 0 || fh == 0 || output_dir == 0 || pending_dirs == 0 || scratch == 0) {
        raze_diag_set("internal bad arguments while extracting entry");
        return RAZE_STATUS_BAD_ARGUMENT;
    }

    solid_stream = (archive_is_solid || fh->solid) && !fh->is_dir;
    if (!solid_stream) {
        raze_compressed_scratch_reset_solid_stream(scratch);
    }

    status = raze_path_guard_join(output_dir, fh->name, fh->host_os, out_path, sizeof(out_path));
    if (status != RAZE_STATUS_OK) {
        raze_diag_set("unsafe or invalid output path for entry '%s'", fh->name);
        return status;
    }

    if (fh->is_dir) {
        mode_t dir_mode = 0;
        int has_mode = raze_fs_compute_mode(fh->host_os, fh->file_attr, 1, &dir_mode);
        int has_mtime = fh->mtime_present;
        time_t dir_mtime = (time_t)fh->unix_mtime;

        if (options != 0 && options->verbose && !options->quiet) {
            printf("mkdir %s\n", out_path);
        }

        status = raze_path_guard_make_dirs(out_path);
        if (status != RAZE_STATUS_OK) {
            raze_diag_set("cannot create directory '%s'", out_path);
            return status;
        }

        if (!skip_forward(payload_stream, payload_size)) {
            raze_diag_set("cannot skip payload for directory entry '%s'", fh->name);
            return RAZE_STATUS_BAD_ARCHIVE;
        }

        return pending_dir_meta_list_add(
            pending_dirs,
            out_path,
            has_mode,
            dir_mode,
            has_mtime,
            dir_mtime
        );
    }

    status = raze_path_guard_make_parent_dirs(out_path);
    if (status != RAZE_STATUS_OK) {
        raze_diag_set("cannot create parent directories for '%s'", out_path);
        return status;
    }

    if (stat(out_path, &st) == 0) {
        RazeOverwriteStats overwrite_stats;
        RazeOverwriteDecision decision;

        if (S_ISDIR(st.st_mode)) {
            raze_diag_set("output path is an existing directory: '%s'", out_path);
            return RAZE_STATUS_IO;
        }

        overwrite_stats.existing_size = (uint64_t)st.st_size;
        overwrite_stats.existing_mtime = st.st_mtime;
        overwrite_stats.existing_mtime_present = 1;
        overwrite_stats.archive_size = fh->unp_size;
        overwrite_stats.archive_mtime = (time_t)fh->unix_mtime;
        overwrite_stats.archive_mtime_present = fh->mtime_present;

        decision = raze_overwrite_prompt_decide(prompt, out_path, &overwrite_stats);
        if (decision == RAZE_OVERWRITE_DECISION_ABORT) {
            raze_diag_set("overwrite prompt aborted for '%s'", out_path);
            return RAZE_STATUS_ABORTED;
        }
        if (decision == RAZE_OVERWRITE_DECISION_ERROR) {
            raze_diag_set("overwrite rejected for existing file '%s'", out_path);
            return RAZE_STATUS_EXISTS;
        }
        if (decision == RAZE_OVERWRITE_DECISION_SKIP) {
            if (solid_stream) {
                status = decode_payload(
                    payload_stream,
                    0,
                    fh,
                    scratch,
                    1,
                    options != 0 ? options->password : 0,
                    options != 0 ? options->password_present : 0
                );
                if (status != RAZE_STATUS_OK) {
                    if (diag_is_empty()) {
                        raze_diag_set("cannot decode skipped solid entry '%s'", fh->name);
                    }
                    return status;
                }
            } else if (!skip_forward(payload_stream, payload_size)) {
                raze_diag_set("cannot skip payload for '%s'", fh->name);
                return RAZE_STATUS_BAD_ARCHIVE;
            }

            if (options != 0 && options->verbose && !options->quiet) {
                printf("skip %s\n", out_path);
            }
            return RAZE_STATUS_OK;
        }
    } else if (errno != ENOENT) {
        raze_diag_set("cannot stat output path '%s': %s", out_path, strerror(errno));
        return RAZE_STATUS_IO;
    }

    if (options != 0 && options->verbose && !options->quiet) {
        printf("extract %s\n", out_path);
    }

    output = fopen(out_path, "wb");
    if (output == 0) {
        raze_diag_set("cannot create output file '%s': %s", out_path, strerror(errno));
        return RAZE_STATUS_IO;
    }

    status = decode_payload(
        payload_stream,
        output,
        fh,
        scratch,
        solid_stream,
        options != 0 ? options->password : 0,
        options != 0 ? options->password_present : 0
    );
    if (fclose(output) != 0 && status == RAZE_STATUS_OK) {
        raze_diag_set("flush/close failed for '%s': %s", out_path, strerror(errno));
        status = RAZE_STATUS_IO;
    }
    output = 0;

    if (status == RAZE_STATUS_OK) {
        apply_entry_metadata(fh, out_path, options != 0 ? options->quiet : 0);
    } else if (diag_is_empty()) {
        raze_diag_set("failed to extract entry '%s' to '%s'", fh->name, out_path);
    }

    if (status == RAZE_STATUS_CRC_MISMATCH || status == RAZE_STATUS_IO || status == RAZE_STATUS_BAD_ARCHIVE) {
        remove_output = 1;
    }

    if (output != 0) {
        fclose(output);
    }
    if (remove_output) {
        remove(out_path);
    }
    return status;
}

static RazeStatus handle_file_block(
    FILE *archive,
    const RazeRar5BlockHeader *block,
    const unsigned char *buf,
    size_t buf_len,
    const char *output_dir,
    const RazeExtractOptions *options,
    int archive_is_solid,
    RazeOverwritePrompt *prompt,
    PendingDirMetaList *pending_dirs,
    RazeCompressedScratch *scratch
) {
    RazeRar5FileHeader fh;
    RazeStatus status;

    memset(&fh, 0, sizeof(fh));

    status = raze_rar5_parse_file_header(block, buf, buf_len, &fh);
    if (status != RAZE_STATUS_OK) {
        return status;
    }

    status = ensure_supported_file(&fh, 0);
    if (status == RAZE_STATUS_OK) {
        status = extract_file_entry(
            archive,
            block->data_size,
            &fh,
            output_dir,
            options,
            archive_is_solid,
            prompt,
            pending_dirs,
            scratch
        );
    }

    raze_rar5_file_header_free(&fh);
    return status;
}

static RazeStatus extract_pending_split_file(
    PendingSplitFile *pending,
    const char *output_dir,
    const RazeExtractOptions *options,
    int archive_is_solid,
    RazeOverwritePrompt *prompt,
    PendingDirMetaList *pending_dirs,
    RazeCompressedScratch *scratch
) {
    FILE *payload_stream;
    RazeStatus status;
    size_t written = 0;

    if (pending == 0 || !pending->active || pending->header.name == 0) {
        return RAZE_STATUS_BAD_ARGUMENT;
    }

    payload_stream = tmpfile();
    if (payload_stream == 0) {
        return RAZE_STATUS_IO;
    }

    while (written < pending->packed_size) {
        size_t n = fwrite(
            pending->packed_data + written,
            1,
            pending->packed_size - written,
            payload_stream
        );
        if (n == 0) {
            fclose(payload_stream);
            return RAZE_STATUS_IO;
        }
        written += n;
    }
    if (fseek(payload_stream, 0, SEEK_SET) != 0) {
        fclose(payload_stream);
        return RAZE_STATUS_IO;
    }

    pending->header.pack_size = pending->packed_size;
    status = extract_file_entry(
        payload_stream,
        pending->packed_size,
        &pending->header,
        output_dir,
        options,
        archive_is_solid,
        prompt,
        pending_dirs,
        scratch
    );
    fclose(payload_stream);
    return status;
}

static RazeStatus handle_split_file_block(
    FILE *archive,
    const RazeRar5BlockHeader *block,
    const unsigned char *buf,
    size_t buf_len,
    PendingSplitFile *pending,
    const char *output_dir,
    const RazeExtractOptions *options,
    int archive_is_solid,
    RazeOverwritePrompt *prompt,
    PendingDirMetaList *pending_dirs,
    RazeCompressedScratch *scratch
) {
    RazeRar5FileHeader fh;
    RazeStatus status;

    if (archive == 0 || block == 0 || pending == 0) {
        return RAZE_STATUS_BAD_ARGUMENT;
    }

    memset(&fh, 0, sizeof(fh));
    status = raze_rar5_parse_file_header(block, buf, buf_len, &fh);
    if (status != RAZE_STATUS_OK) {
        return status;
    }

    status = ensure_supported_file(&fh, 1);
    if (status != RAZE_STATUS_OK) {
        raze_rar5_file_header_free(&fh);
        return status;
    }

    if (!pending->active) {
        if (fh.split_before || !fh.split_after) {
            raze_rar5_file_header_free(&fh);
            return RAZE_STATUS_BAD_ARCHIVE;
        }

        pending_split_file_reset(pending);
        if (!file_header_clone(&fh, &pending->header)) {
            raze_rar5_file_header_free(&fh);
            return RAZE_STATUS_IO;
        }
        pending->header.hash_present = 0;
        pending->header.hash_is_packed_part = 0;
        memset(pending->header.hash_value, 0, sizeof(pending->header.hash_value));
        pending->active = 1;
        pending->packed_size = 0;
    } else {
        if (!fh.split_before) {
            raze_rar5_file_header_free(&fh);
            return RAZE_STATUS_BAD_ARCHIVE;
        }
        if (!pending_split_headers_compatible(pending, &fh)) {
            raze_rar5_file_header_free(&fh);
            return RAZE_STATUS_BAD_ARCHIVE;
        }
    }

    if (fh.crc32_present) {
        pending->header.crc32_present = 1;
        pending->header.crc32 = fh.crc32;
    }
    if (fh.mtime_present) {
        pending->header.mtime_present = 1;
        pending->header.unix_mtime = fh.unix_mtime;
    }
    if (fh.encrypted) {
        pending->header.crypt_use_hash_key = fh.crypt_use_hash_key;
        pending->header.crypt_use_psw_check = fh.crypt_use_psw_check;
        pending->header.crypt_lg2_count = fh.crypt_lg2_count;
        pending->header.crypt_version = fh.crypt_version;
        memcpy(pending->header.crypt_salt, fh.crypt_salt, sizeof(fh.crypt_salt));
        memcpy(pending->header.crypt_initv, fh.crypt_initv, sizeof(fh.crypt_initv));
        memcpy(pending->header.crypt_psw_check, fh.crypt_psw_check, sizeof(fh.crypt_psw_check));
        memcpy(pending->header.crypt_psw_check_csum,
               fh.crypt_psw_check_csum,
               sizeof(fh.crypt_psw_check_csum));
    }
    if (fh.hash_present && !fh.hash_is_packed_part) {
        pending->header.hash_present = 1;
        pending->header.hash_type = fh.hash_type;
        pending->header.hash_is_packed_part = 0;
        memcpy(pending->header.hash_value, fh.hash_value, sizeof(fh.hash_value));
    }
    pending->header.split_before = 0;
    pending->header.split_after = fh.split_after ? 1 : 0;

    status = pending_split_append_data(
        pending,
        archive,
        block->data_size,
        &fh,
        options
    );
    if (status != RAZE_STATUS_OK) {
        raze_rar5_file_header_free(&fh);
        return status;
    }

    if (!fh.split_after) {
        pending->header.split_after = 0;
        status = extract_pending_split_file(
            pending,
            output_dir,
            options,
            archive_is_solid,
            prompt,
            pending_dirs,
            scratch
        );
        pending_split_file_reset(pending);
    }

    raze_rar5_file_header_free(&fh);
    return status;
}

RazeStatus raze_extract_store_archive(
    const char *archive_path,
    const char *output_dir,
    const RazeExtractOptions *options
) {
    FILE *file = 0;
    RazeOverwritePrompt prompt;
    PendingDirMetaList pending_dirs;
    PendingSplitFile pending_split;
    RazeCompressedScratch compressed_scratch;
    HeaderCryptState header_crypt;
    RazeVolumeChain volumes;
    RazeExtractOptions local_options;
    size_t volume_index;
    int archive_is_solid = 0;
    int archive_is_multivolume = 0;
    int saw_main = 0;
    int saw_end = 0;
    RazeStatus status;
    RazeRar5ReadResult rr;

    memset(&pending_dirs, 0, sizeof(pending_dirs));
    memset(&pending_split, 0, sizeof(pending_split));
    header_crypt_reset(&header_crypt);
    memset(&volumes, 0, sizeof(volumes));
    enc_profile_reset();
    raze_compressed_scratch_init(&compressed_scratch);

    if (archive_path == 0 || output_dir == 0) {
        raze_diag_set("archive path and output dir are required");
        return RAZE_STATUS_BAD_ARGUMENT;
    }

    if (options == 0) {
        local_options = raze_extract_options_default();
        options = &local_options;
    }

    status = raze_path_guard_make_dirs(output_dir);
    if (status != RAZE_STATUS_OK) {
        raze_diag_set("cannot create output root '%s'", output_dir);
        goto cleanup;
    }

    status = raze_volume_chain_discover(archive_path, &volumes);
    if (status != RAZE_STATUS_OK) {
        raze_diag_set("cannot discover archive volume chain from '%s'", archive_path);
        goto cleanup;
    }

    raze_overwrite_prompt_init(&prompt, options->overwrite_mode);

    for (volume_index = 0; volume_index < volumes.count; ++volume_index) {
        int saw_main_in_volume = 0;
        header_crypt_reset(&header_crypt);

        file = fopen(volumes.paths[volume_index], "rb");
        if (file == 0) {
            raze_diag_set("cannot open volume '%s': %s",
                          volumes.paths[volume_index], strerror(errno));
            status = RAZE_STATUS_IO;
            goto cleanup;
        }

        status = raze_rar5_read_signature(file);
        if (status != RAZE_STATUS_OK) {
            if (diag_is_empty()) {
                raze_diag_set("invalid or missing RAR5 signature in '%s'",
                              volumes.paths[volume_index]);
            }
            goto cleanup;
        }

        for (;;) {
            RazeRar5BlockHeader block;
            unsigned char *buf = 0;
            size_t buf_len = 0;
            int end_of_volume = 0;

            rr = read_block_with_header_crypt(file, &header_crypt, &block, &buf, &buf_len, &status);
            if (rr == RAZE_RAR5_READ_EOF) {
                free(buf);
                break;
            }
            if (rr == RAZE_RAR5_READ_ERROR) {
                if (diag_is_empty()) {
                    long pos = ftell(file);
                    if (pos < 0) {
                        pos = 0;
                    }
                    raze_diag_set("failed reading block in '%s' near offset %llu",
                                  volumes.paths[volume_index],
                                  (unsigned long long)pos);
                }
                free(buf);
                goto cleanup;
            }

            switch (block.header_type) {
                case RAZE_RAR5_HEAD_MAIN: {
                    uint64_t arc_flags = 0;
                    size_t consumed = 0;
                    size_t cursor = block.body_offset;
                    int volume_flag;

                    saw_main = 1;
                    saw_main_in_volume = 1;
                    if (!raze_vint_decode(buf + cursor, block.extra_offset - cursor, &consumed, &arc_flags)) {
                        raze_diag_set("malformed %s at offset %llu in '%s'",
                                      header_type_name(block.header_type),
                                      (unsigned long long)block.header_offset,
                                      volumes.paths[volume_index]);
                        status = RAZE_STATUS_BAD_ARCHIVE;
                        free(buf);
                        goto cleanup;
                    }

                    volume_flag = (arc_flags & RAZE_RAR5_MHFL_VOLUME) != 0;
                    if (volume_index == 0) {
                        archive_is_solid = (arc_flags & RAZE_RAR5_MHFL_SOLID) != 0;
                        archive_is_multivolume = volume_flag;
                        if (volumes.count > 1U && !volume_flag) {
                            raze_diag_set("first volume '%s' does not carry multivolume flag",
                                          volumes.paths[volume_index]);
                            status = RAZE_STATUS_BAD_ARCHIVE;
                            free(buf);
                            goto cleanup;
                        }
                    } else if (!volume_flag) {
                        raze_diag_set("volume '%s' misses required multivolume flag",
                                      volumes.paths[volume_index]);
                        status = RAZE_STATUS_BAD_ARCHIVE;
                        free(buf);
                        goto cleanup;
                    }

                    if (!skip_forward(file, block.data_size)) {
                        raze_diag_set("cannot skip payload for %s at offset %llu in '%s'",
                                      header_type_name(block.header_type),
                                      (unsigned long long)block.header_offset,
                                      volumes.paths[volume_index]);
                        status = RAZE_STATUS_BAD_ARCHIVE;
                        free(buf);
                        goto cleanup;
                    }
                    break;
                }
                case RAZE_RAR5_HEAD_FILE:
                    if (pending_split.active ||
                        (block.flags & (RAZE_RAR5_HFL_SPLITBEFORE | RAZE_RAR5_HFL_SPLITAFTER)) != 0) {
                        status = handle_split_file_block(
                            file,
                            &block,
                            buf,
                            buf_len,
                            &pending_split,
                            output_dir,
                            options,
                            archive_is_solid,
                            &prompt,
                            &pending_dirs,
                            &compressed_scratch
                        );
                    } else {
                        status = handle_file_block(
                            file,
                            &block,
                            buf,
                            buf_len,
                            output_dir,
                            options,
                            archive_is_solid,
                            &prompt,
                            &pending_dirs,
                            &compressed_scratch
                        );
                    }
                    if (status != RAZE_STATUS_OK) {
                        if (diag_is_empty()) {
                            raze_diag_set("failed handling %s '%s' at offset %llu in '%s'",
                                          header_type_name(block.header_type),
                                          block.header_type == RAZE_RAR5_HEAD_FILE ? "file" : "split",
                                          (unsigned long long)block.header_offset,
                                          volumes.paths[volume_index]);
                        }
                        free(buf);
                        goto cleanup;
                    }
                    break;
                case RAZE_RAR5_HEAD_SERVICE: {
                    RazeRar5FileHeader service_header;
                    memset(&service_header, 0, sizeof(service_header));
                    status = raze_rar5_parse_file_header(&block, buf, buf_len, &service_header);
                    if (status != RAZE_STATUS_OK) {
                        if (status == RAZE_STATUS_UNSUPPORTED_FEATURE) {
                            raze_diag_set("unsupported %s feature at offset %llu in '%s'",
                                          header_type_name(block.header_type),
                                          (unsigned long long)block.header_offset,
                                          volumes.paths[volume_index]);
                        } else {
                            raze_diag_set("malformed %s at offset %llu in '%s'",
                                          header_type_name(block.header_type),
                                          (unsigned long long)block.header_offset,
                                          volumes.paths[volume_index]);
                        }
                        free(buf);
                        goto cleanup;
                    }
                    if (!skip_forward(file, block.data_size)) {
                        raze_diag_set("cannot skip payload for %s at offset %llu in '%s'",
                                      header_type_name(block.header_type),
                                      (unsigned long long)block.header_offset,
                                      volumes.paths[volume_index]);
                        status = RAZE_STATUS_BAD_ARCHIVE;
                        raze_rar5_file_header_free(&service_header);
                        free(buf);
                        goto cleanup;
                    }
                    raze_rar5_file_header_free(&service_header);
                    break;
                }
                case RAZE_RAR5_HEAD_CRYPT:
                    status = parse_head_crypt(&block, buf, buf_len, options, &header_crypt);
                    if (status != RAZE_STATUS_OK) {
                        if (diag_is_empty()) {
                            raze_diag_set("failed parsing %s at offset %llu in '%s'",
                                          header_type_name(block.header_type),
                                          (unsigned long long)block.header_offset,
                                          volumes.paths[volume_index]);
                        }
                        free(buf);
                        goto cleanup;
                    }
                    if (!skip_forward(file, block.data_size)) {
                        raze_diag_set("cannot skip payload for %s at offset %llu in '%s'",
                                      header_type_name(block.header_type),
                                      (unsigned long long)block.header_offset,
                                      volumes.paths[volume_index]);
                        status = RAZE_STATUS_BAD_ARCHIVE;
                        free(buf);
                        goto cleanup;
                    }
                    break;
                case RAZE_RAR5_HEAD_ENDARC:
                    saw_end = 1;
                    if (!skip_forward(file, block.data_size)) {
                        raze_diag_set("cannot skip payload for %s at offset %llu in '%s'",
                                      header_type_name(block.header_type),
                                      (unsigned long long)block.header_offset,
                                      volumes.paths[volume_index]);
                        status = RAZE_STATUS_BAD_ARCHIVE;
                        free(buf);
                        goto cleanup;
                    }
                    end_of_volume = 1;
                    break;
                default:
                    if (!skip_forward(file, block.data_size)) {
                        raze_diag_set("cannot skip payload for %s at offset %llu in '%s'",
                                      header_type_name(block.header_type),
                                      (unsigned long long)block.header_offset,
                                      volumes.paths[volume_index]);
                        status = RAZE_STATUS_BAD_ARCHIVE;
                        free(buf);
                        goto cleanup;
                    }
                    break;
            }

            if (status == RAZE_STATUS_CRC_MISMATCH && header_crypt.enabled) {
                free(buf);
                goto cleanup;
            }

            free(buf);
            if (end_of_volume) {
                break;
            }
        }

        if (!saw_main_in_volume) {
            raze_diag_set("volume '%s' is missing main header", volumes.paths[volume_index]);
            status = RAZE_STATUS_BAD_ARCHIVE;
            goto cleanup;
        }
        if (pending_split.active && volume_index + 1U >= volumes.count) {
            raze_diag_set("missing next volume while assembling split file after '%s'",
                          volumes.paths[volume_index]);
            status = RAZE_STATUS_IO;
            goto cleanup;
        }

        fclose(file);
        file = 0;
    }

    if (!saw_main || !saw_end) {
        raze_diag_set("archive is missing required main/end headers");
        status = RAZE_STATUS_BAD_ARCHIVE;
        goto cleanup;
    }
    if (archive_is_multivolume && volumes.count == 1U) {
        raze_diag_set("archive declares multivolume but only one volume was found");
        status = RAZE_STATUS_IO;
        goto cleanup;
    }

    apply_pending_dir_metadata(&pending_dirs, options->quiet);
    status = RAZE_STATUS_OK;

cleanup:
    enc_profile_report(archive_path);
    pending_split_file_free(&pending_split);
    pending_dir_meta_list_free(&pending_dirs);
    raze_compressed_scratch_free(&compressed_scratch);
    raze_volume_chain_free(&volumes);
    if (file != 0) {
        fclose(file);
    }
    return status;
}
