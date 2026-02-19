#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../cli/match.h"
#include "../format/rar5/block_reader.h"
#include "../format/rar5/file_header.h"
#include "decode_internal.h"

#define RAZE_RAR5_HEAD_MAIN 1U
#define RAZE_RAR5_HEAD_FILE 2U
#define RAZE_RAR5_HEAD_SERVICE 3U
#define RAZE_RAR5_HEAD_CRYPT 4U
#define RAZE_RAR5_HEAD_ENDARC 5U
#define RAZE_RAR5_HASH_VALUE_SIZE 32U

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

static const char *hash_type_name(const RazeRar5FileHeader *fh)
{
	if (fh == 0 || !fh->hash_present) {
		return "none";
	}
	if (fh->hash_type == RAZE_RAR5_HASH_TYPE_BLAKE2SP) {
		return "blake2sp";
	}
	return "unknown";
}

static void hash_to_hex(
	const unsigned char *hash,
	size_t hash_len,
	char *out,
	size_t out_len
)
{
	static const char hexdigits[] = "0123456789abcdef";
	size_t i;

	if (out == 0 || out_len == 0U) {
		return;
	}
	if (hash == 0 || hash_len == 0U || out_len < (hash_len * 2U + 1U)) {
		out[0] = '\0';
		return;
	}

	for (i = 0; i < hash_len; ++i) {
		out[i * 2U] = hexdigits[(hash[i] >> 4U) & 0x0fU];
		out[i * 2U + 1U] = hexdigits[hash[i] & 0x0fU];
	}
	out[hash_len * 2U] = '\0';
}

static void print_entry(
    const RazeRar5FileHeader *fh,
    int technical,
    int is_service
) {
    char hash_hex[RAZE_RAR5_HASH_VALUE_SIZE * 2U + 1U];

    if (fh == 0 || fh->name == 0) {
        return;
    }

    if (!technical) {
        if (!is_service) {
            printf("%10llu %s%s\n",
                (unsigned long long)fh->unp_size,
                fh->name,
                fh->is_dir ? "/" : "");
        }
        return;
    }

    hash_to_hex(
        fh->hash_present ? fh->hash_value : 0,
        fh->hash_present ? RAZE_RAR5_HASH_VALUE_SIZE : 0U,
        hash_hex,
        sizeof(hash_hex)
    );

    printf(
        "type=%s name=%s%s method=%llu pack=%llu unp=%llu host_os=%llu split_before=%d split_after=%d hash_type=%s hash_scope=%s hash_mac=%d hash=%s\n",
        is_service ? "service" : "file",
        fh->name,
        fh->is_dir ? "/" : "",
        (unsigned long long)fh->method,
        (unsigned long long)fh->pack_size,
        (unsigned long long)fh->unp_size,
        (unsigned long long)fh->host_os,
        fh->split_before,
        fh->split_after,
        hash_type_name(fh),
        fh->hash_present ? (fh->hash_is_packed_part ? "packed-part" : "unpacked") : "none",
        fh->crypt_use_hash_key ? 1 : 0,
        fh->hash_present ? hash_hex : "-"
    );
}

RazeStatus raze_list_rar5_archive(const char *archive_path, int technical)
{
	RazeExtractOptions options;

	options = raze_extract_options_default();
	return raze_list_rar5_archive_with_options(archive_path, technical,
						   &options);
}

RazeStatus raze_list_rar5_archive_with_options(
	const char *archive_path,
	int technical,
	const RazeExtractOptions *options
)
{
    FILE *file;
    RazeStatus status;
    RazeRar5ReadResult rr;
    int saw_main = 0;
    int saw_end = 0;
	RazeExtractOptions local_options;
	RazeMatchRules rules;

	if (archive_path == 0) {
		raze_diag_set("archive path is required");
		return RAZE_STATUS_BAD_ARGUMENT;
	}
	if (options == 0) {
		local_options = raze_extract_options_default();
		options = &local_options;
	}
	memset(&rules, 0, sizeof(rules));
	rules.ap_prefix = options->ap_prefix;
	rules.recurse = options->recurse;
	rules.includes = options->include_masks;
	rules.include_count = options->include_mask_count;
	rules.excludes = options->exclude_masks;
	rules.exclude_count = options->exclude_mask_count;

	file = fopen(archive_path, "rb");
	if (file == 0) {
		raze_diag_set("cannot open archive '%s': %s", archive_path, strerror(errno));
		return RAZE_STATUS_IO;
	}

	status = raze_rar5_read_signature(file);
	if (status != RAZE_STATUS_OK) {
		raze_diag_set("invalid or missing RAR5 signature in '%s'", archive_path);
		fclose(file);
		return status;
	}

    for (;;) {
        RazeRar5BlockHeader block;
        unsigned char *buf = 0;
        size_t buf_len = 0;

        rr = raze_rar5_read_block(file, &block, &buf, &buf_len, &status);
        if (rr == RAZE_RAR5_READ_EOF) {
            break;
        }
		if (rr == RAZE_RAR5_READ_ERROR) {
			long pos = ftell(file);
			if (pos < 0) {
				pos = 0;
			}
			raze_diag_set("failed reading block in '%s' near offset %llu",
				      archive_path,
				      (unsigned long long)pos);
			free(buf);
			fclose(file);
			return status;
		}

        switch (block.header_type) {
            case RAZE_RAR5_HEAD_MAIN:
                saw_main = 1;
                break;
            case RAZE_RAR5_HEAD_FILE:
            case RAZE_RAR5_HEAD_SERVICE: {
                RazeRar5FileHeader fh;
				status = raze_rar5_parse_file_header(&block, buf, buf_len, &fh);
				if (status != RAZE_STATUS_OK) {
					if (status == RAZE_STATUS_UNSUPPORTED_FEATURE) {
						raze_diag_set(
							"unsupported %s feature at offset %llu in '%s'",
							header_type_name(block.header_type),
							(unsigned long long)block.header_offset,
							archive_path
						);
					} else {
						raze_diag_set(
							"malformed %s at offset %llu in '%s'",
							header_type_name(block.header_type),
							(unsigned long long)block.header_offset,
							archive_path
						);
					}
					free(buf);
					fclose(file);
					return status;
                }
		if (raze_match_entry_path(fh.name, &rules)) {
			print_entry(&fh, technical,
				    block.header_type == RAZE_RAR5_HEAD_SERVICE);
		}
                raze_rar5_file_header_free(&fh);
                break;
            }
			case RAZE_RAR5_HEAD_CRYPT:
				raze_diag_set(
					"encrypted headers are not supported in list mode for '%s'",
					archive_path
				);
				free(buf);
				fclose(file);
				return RAZE_STATUS_UNSUPPORTED_FEATURE;
            case RAZE_RAR5_HEAD_ENDARC:
                saw_end = 1;
                break;
            default:
                break;
        }

        free(buf);

		if (!skip_forward(file, block.data_size)) {
			raze_diag_set(
				"cannot skip payload for %s at offset %llu in '%s'",
				header_type_name(block.header_type),
				(unsigned long long)block.header_offset,
				archive_path
			);
			fclose(file);
			return RAZE_STATUS_BAD_ARCHIVE;
		}
    }

    fclose(file);

	if (!saw_main || !saw_end) {
		raze_diag_set(
			"archive '%s' is missing required main/end headers",
			archive_path
		);
		return RAZE_STATUS_BAD_ARCHIVE;
	}

    return RAZE_STATUS_OK;
}
