#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVE_STORE="$ROOT_DIR/corpus/local/archives/local_store.rar"
ARCHIVE_FAST="$ROOT_DIR/corpus/local/archives/local_fast.rar"
SOURCE_DIR="$ROOT_DIR/corpus/local/source"
RAR_BIN="${RAR_BIN:-$(command -v rar || true)}"

log() {
    printf '[test] %s\n' "$*"
}

fail() {
    printf '[test] error: %s\n' "$*" >&2
    exit 1
}

run_expect_exit() {
    local expected="$1"
    shift
    local rc
    set +e
    "$@"
    rc=$?
    set -e
    if [[ "$rc" -ne "$expected" ]]; then
        fail "expected exit $expected, got $rc for command: $*"
    fi
}

dir_hash() {
    local dir="$1"
    (
        cd "$dir"
        find . -type f -print0 | sort -z | xargs -0 sha256sum
    ) | sha256sum | awk '{print $1}'
}

log "ensuring local corpus exists"
"$ROOT_DIR/scripts/corpus_build_local.sh"

[[ -f "$ARCHIVE_STORE" ]] || fail "missing $ARCHIVE_STORE"
[[ -f "$ARCHIVE_FAST" ]] || fail "missing $ARCHIVE_FAST"
[[ -d "$SOURCE_DIR" ]] || fail "missing $SOURCE_DIR"
[[ -n "$RAR_BIN" ]] || fail "rar binary not found. Set RAR_BIN or install rar."

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

log "running parser unit tests"
PARSER_UNIT_BIN="$TMP_DIR/parser_units"
cc -std=c11 -O2 -Wall -Wextra -Wpedantic \
    -I"$ROOT_DIR/include" \
    "$ROOT_DIR/tests/test_parser_units.c" \
    "$ROOT_DIR/src/format/rar5/vint.c" \
    "$ROOT_DIR/src/format/rar5/block_reader.c" \
    "$ROOT_DIR/src/checksum/crc32.c" \
    -o "$PARSER_UNIT_BIN"
"$PARSER_UNIT_BIN"

OUT_DIR="$TMP_DIR/out_store"
log "extracting store archive and checking file contents"
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op"$OUT_DIR" "$ARCHIVE_STORE"

SRC_HASH="$(dir_hash "$SOURCE_DIR")"
DST_HASH="$(dir_hash "$OUT_DIR")"
if [[ "$SRC_HASH" != "$DST_HASH" ]]; then
    fail "source/extracted directory hash mismatch"
fi

log "checking list command output"
LIST_OUT="$TMP_DIR/list_output.txt"
set +e
"$ROOT_DIR/raze" l "$ARCHIVE_STORE" > "$LIST_OUT"
rc=$?
set -e
if [[ "$rc" -ne 0 ]]; then
    fail "list command failed with exit $rc"
fi
if ! grep -Fq "small_text.txt" "$LIST_OUT"; then
    fail "list output missing expected file small_text.txt"
fi
if ! grep -Fq "tree/file_1.txt" "$LIST_OUT"; then
    fail "list output missing expected nested file tree/file_1.txt"
fi

log "checking technical list command output"
LIST_TECH_OUT="$TMP_DIR/list_technical_output.txt"
set +e
"$ROOT_DIR/raze" lt "$ARCHIVE_STORE" > "$LIST_TECH_OUT"
rc=$?
set -e
if [[ "$rc" -ne 0 ]]; then
    fail "technical list command failed with exit $rc"
fi
if ! grep -Fq "type=file" "$LIST_TECH_OUT"; then
    fail "technical list output missing type metadata"
fi

log "checking non-overwrite collision path (non-tty should fail)"
run_expect_exit 7 "$ROOT_DIR/raze" x -idq -op"$OUT_DIR" "$ARCHIVE_STORE"

log "checking forced overwrite path"
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op"$OUT_DIR" "$ARCHIVE_STORE"

log "checking -o switch compatibility (bare -o must be rejected)"
run_expect_exit 2 "$ROOT_DIR/raze" x -idq -o "$ARCHIVE_STORE"

log "checking SFX-prefixed archive signature scan"
dd if=/dev/zero of="$TMP_DIR/sfx_prefix.bin" bs=1 count=512 status=none
cat "$TMP_DIR/sfx_prefix.bin" "$ARCHIVE_STORE" > "$TMP_DIR/sfx_store.rar"
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op"$TMP_DIR/out_sfx" "$TMP_DIR/sfx_store.rar"
SFX_HASH="$(dir_hash "$TMP_DIR/out_sfx")"
if [[ "$SRC_HASH" != "$SFX_HASH" ]]; then
    fail "SFX-prefixed archive extraction mismatch"
fi

log "checking unsupported compressed method archive"
run_expect_exit 3 "$ROOT_DIR/raze" x -idq -op"$TMP_DIR/out_fast" "$ARCHIVE_FAST"

log "checking long archive path support (>1024 bytes)"
LONG_SRC_DIR="$TMP_DIR/long_src"
LONG_OUT_DIR="$TMP_DIR/out_long"
LONG_ARCHIVE="$TMP_DIR/long_store.rar"
LONG_SEGMENT="segment0123456789segment0123456789"
LONG_REL_DIR=""
while [[ ${#LONG_REL_DIR} -le 1100 ]]; do
    if [[ -z "$LONG_REL_DIR" ]]; then
        LONG_REL_DIR="$LONG_SEGMENT"
    else
        LONG_REL_DIR="$LONG_REL_DIR/$LONG_SEGMENT"
    fi
done
LONG_REL_FILE="$LONG_REL_DIR/leaf.txt"
mkdir -p "$LONG_SRC_DIR/$LONG_REL_DIR"
printf 'long path fixture\n' > "$LONG_SRC_DIR/$LONG_REL_FILE"
if [[ ${#LONG_REL_FILE} -le 1024 ]]; then
    fail "long path fixture is not long enough: ${#LONG_REL_FILE}"
fi
(
    cd "$LONG_SRC_DIR"
    "$RAR_BIN" a -idq -ma5 -m0 -s- -r "$LONG_ARCHIVE" .
)
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op"$LONG_OUT_DIR" "$LONG_ARCHIVE"
if [[ ! -f "$LONG_OUT_DIR/$LONG_REL_FILE" ]]; then
    fail "extracted long path file is missing"
fi
if ! cmp -s "$LONG_SRC_DIR/$LONG_REL_FILE" "$LONG_OUT_DIR/$LONG_REL_FILE"; then
    fail "extracted long path file content mismatch"
fi

log "checking bad archive detection with truncated input"
STORE_SIZE="$(stat -c%s "$ARCHIVE_STORE")"
if [[ "$STORE_SIZE" -le 256 ]]; then
    fail "store archive unexpectedly small for truncation test"
fi
dd if="$ARCHIVE_STORE" of="$TMP_DIR/truncated.rar" bs=1 count=$((STORE_SIZE / 2)) status=none
run_expect_exit 4 "$ROOT_DIR/raze" x -idq -op"$TMP_DIR/out_bad" "$TMP_DIR/truncated.rar"

log "all tests passed"
