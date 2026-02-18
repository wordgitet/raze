#ifndef RAZE_DECODE_INTERNAL_H
#define RAZE_DECODE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

#include "raze/raze.h"

typedef struct RazeRar5BlockHeader {
    uint64_t header_offset;
    uint64_t data_offset;
    uint64_t next_offset;
    uint64_t header_type;
    uint64_t flags;
    uint64_t header_size;
    uint64_t data_size;
    uint64_t extra_size;
    uint32_t header_crc;
    int crc_ok;
    size_t body_offset;
    size_t extra_offset;
} RazeRar5BlockHeader;

typedef struct RazeRar5FileHeader {
    char *name;
    size_t name_len;
    uint64_t file_flags;
    uint64_t method;
    uint64_t comp_version;
    uint64_t dict_base_log2;
    uint64_t dict_extra_scale;
    uint64_t dict_size_bytes;
    uint64_t unp_size;
    uint64_t pack_size;
    uint64_t file_attr;
    uint64_t host_os;
    uint32_t unix_mtime;
    uint32_t crc32;
    unsigned char crypt_salt[16];
    unsigned char crypt_initv[16];
    unsigned char crypt_psw_check[8];
    unsigned char crypt_psw_check_csum[4];
    uint8_t crypt_lg2_count;
    uint8_t crypt_version;
    uint8_t crypt_use_psw_check;
    uint8_t crypt_use_hash_key;
    int mtime_present;
    int crc32_present;
    int split_before;
    int split_after;
    int solid;
    int is_dir;
    int encrypted;
    int comp_is_v50_compat;
} RazeRar5FileHeader;

typedef struct RazeRar5Scan {
    int is_rar5;
    int saw_main_header;
    int saw_end_archive;
    int has_encryption;
    int has_multivolume;
    int has_solid;
    int has_split;
    int has_compressed_method;
    int has_unknown_unp_size;
    uint64_t file_count;
    uint64_t store_file_count;
} RazeRar5Scan;

int rar5_parser_probe(const char *archive_path);
RazeStatus rar5_scan_archive(const char *archive_path, RazeRar5Scan *scan);
int raze_io_validate_input_path(const char *path);
int raze_crc32_selftest(void);
int raze_crypto_selftest(void);
RazeStatus raze_extract_store_archive(
    const char *archive_path,
    const char *output_dir,
    const RazeExtractOptions *options
);
RazeStatus raze_list_rar5_archive(const char *archive_path, int technical);
void raze_diag_set(const char *fmt, ...);

#endif
