#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CC_BIN="${CC:-cc}"
EXTRA_CFLAGS="${EXTRA_CFLAGS:-}"
EXTRA_LDFLAGS="${EXTRA_LDFLAGS:-}"
TMP_DIR="$(mktemp -d)"
PARSER_UNIT_BIN="$TMP_DIR/parser_units"
trap 'rm -rf "$TMP_DIR"' EXIT

# EXTRA_* are intentionally word-split to allow multiple compiler flags.
# shellcheck disable=SC2086
"$CC_BIN" -std=c11 -O2 -Wall -Wextra -Wpedantic \
	-I"$ROOT_DIR/include" \
	$EXTRA_CFLAGS \
	"$ROOT_DIR/tests/test_parser_units.c" \
	"$ROOT_DIR/src/format/rar5/vint.c" \
	"$ROOT_DIR/src/format/rar5/block_reader.c" \
	"$ROOT_DIR/src/format/rar5/file_header.c" \
	"$ROOT_DIR/src/checksum/crc32.c" \
	"$ROOT_DIR/src/io/fs_meta.c" \
	-o "$PARSER_UNIT_BIN" \
	$EXTRA_LDFLAGS

"$PARSER_UNIT_BIN"
