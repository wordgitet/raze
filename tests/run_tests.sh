#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVE_STORE="$ROOT_DIR/corpus/local/archives/local_store.rar"
ARCHIVE_FAST="$ROOT_DIR/corpus/local/archives/local_fast.rar"
ARCHIVE_SOLID="$ROOT_DIR/corpus/local/archives/local_best_solid.rar"
ARCHIVE_THEMATIC_FAST="$ROOT_DIR/corpus/local/thematic/archives/thematic_fast.rar"
ARCHIVE_THEMATIC_SOLID="$ROOT_DIR/corpus/local/thematic/archives/thematic_best_solid.rar"
SOURCE_DIR="$ROOT_DIR/corpus/local/source"
THEMATIC_SOURCE_DIR="$ROOT_DIR/corpus/local/thematic/source"
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

run_expect_exit_one_of() {
    local expected_a="$1"
    local expected_b="$2"
    shift 2
    local rc
    set +e
    "$@"
    rc=$?
    set -e
    if [[ "$rc" -ne "$expected_a" && "$rc" -ne "$expected_b" ]]; then
        fail "expected exit $expected_a or $expected_b, got $rc for command: $*"
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
"$ROOT_DIR/scripts/corpus_build_thematic.sh"

[[ -f "$ARCHIVE_STORE" ]] || fail "missing $ARCHIVE_STORE"
[[ -f "$ARCHIVE_FAST" ]] || fail "missing $ARCHIVE_FAST"
[[ -f "$ARCHIVE_SOLID" ]] || fail "missing $ARCHIVE_SOLID"
[[ -f "$ARCHIVE_THEMATIC_FAST" ]] || fail "missing $ARCHIVE_THEMATIC_FAST"
[[ -f "$ARCHIVE_THEMATIC_SOLID" ]] || fail "missing $ARCHIVE_THEMATIC_SOLID"
[[ -d "$SOURCE_DIR" ]] || fail "missing $SOURCE_DIR"
[[ -d "$THEMATIC_SOURCE_DIR" ]] || fail "missing $THEMATIC_SOURCE_DIR"
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
    "$ROOT_DIR/src/format/rar5/file_header.c" \
    "$ROOT_DIR/src/checksum/crc32.c" \
    "$ROOT_DIR/src/io/fs_meta.c" \
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

log "checking supported compatibility switches for extract"
run_expect_exit 0 "$ROOT_DIR/raze" x -y -idq -op"$TMP_DIR/out_y" "$ARCHIVE_STORE"
run_expect_exit 0 "$ROOT_DIR/raze" x -inul -o+ -op"$TMP_DIR/out_inul" "$ARCHIVE_STORE"
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -psecret -op"$TMP_DIR/out_p" "$ARCHIVE_STORE"

log "checking -o switch compatibility (bare -o must be rejected)"
run_expect_exit 2 "$ROOT_DIR/raze" x -idq -o "$ARCHIVE_STORE"
run_expect_exit 2 "$ROOT_DIR/raze" x -idp "$ARCHIVE_STORE"
run_expect_exit 2 "$ROOT_DIR/raze" l -idq "$ARCHIVE_STORE"

log "checking SFX-prefixed archive signature scan"
dd if=/dev/zero of="$TMP_DIR/sfx_prefix.bin" bs=1 count=512 status=none
cat "$TMP_DIR/sfx_prefix.bin" "$ARCHIVE_STORE" > "$TMP_DIR/sfx_store.rar"
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op"$TMP_DIR/out_sfx" "$TMP_DIR/sfx_store.rar"
SFX_HASH="$(dir_hash "$TMP_DIR/out_sfx")"
if [[ "$SRC_HASH" != "$SFX_HASH" ]]; then
    fail "SFX-prefixed archive extraction mismatch"
fi

log "checking compressed extraction path"
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op"$TMP_DIR/out_fast" "$ARCHIVE_FAST"
FAST_HASH="$(dir_hash "$TMP_DIR/out_fast")"
if [[ "$SRC_HASH" != "$FAST_HASH" ]]; then
    fail "compressed extraction hash mismatch"
fi

log "checking compressed extraction path on thematic corpus"
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op"$TMP_DIR/out_thematic_fast" "$ARCHIVE_THEMATIC_FAST"
THEMATIC_SRC_HASH="$(dir_hash "$THEMATIC_SOURCE_DIR")"
THEMATIC_DST_HASH="$(dir_hash "$TMP_DIR/out_thematic_fast")"
if [[ "$THEMATIC_SRC_HASH" != "$THEMATIC_DST_HASH" ]]; then
    fail "thematic compressed extraction hash mismatch"
fi

log "checking solid extraction path"
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op"$TMP_DIR/out_solid" "$ARCHIVE_SOLID"
SOLID_HASH="$(dir_hash "$TMP_DIR/out_solid")"
if [[ "$SRC_HASH" != "$SOLID_HASH" ]]; then
    fail "solid extraction hash mismatch"
fi

log "checking solid extraction path on thematic corpus"
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op"$TMP_DIR/out_thematic_solid" "$ARCHIVE_THEMATIC_SOLID"
THEMATIC_SOLID_HASH="$(dir_hash "$TMP_DIR/out_thematic_solid")"
if [[ "$THEMATIC_SRC_HASH" != "$THEMATIC_SOLID_HASH" ]]; then
    fail "thematic solid extraction hash mismatch"
fi

log "checking split multivolume extraction (.partN)"
SPLIT_SRC_DIR="$TMP_DIR/split_src"
SPLIT_OUT_DIR="$TMP_DIR/out_split"
SPLIT_ARCHIVE="$TMP_DIR/split_fast.rar"
mkdir -p "$SPLIT_SRC_DIR/dir"
dd if=/dev/urandom of="$SPLIT_SRC_DIR/dir/blob.bin" bs=1K count=450 status=none
printf 'split fixture text\n' > "$SPLIT_SRC_DIR/dir/readme.txt"
(
    cd "$SPLIT_SRC_DIR"
    "$RAR_BIN" a -idq -ma5 -m1 -s- -v120k "$SPLIT_ARCHIVE" ./dir
)
mapfile -t SPLIT_PARTS < <(find "$TMP_DIR" -maxdepth 1 -type f -name 'split_fast.part*.rar' | sort -V)
if [[ "${#SPLIT_PARTS[@]}" -lt 2 ]]; then
    fail "split fixture did not produce multiple volumes"
fi
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op"$SPLIT_OUT_DIR" "$TMP_DIR/split_fast.part1.rar"
if [[ "$(dir_hash "$SPLIT_SRC_DIR")" != "$(dir_hash "$SPLIT_OUT_DIR")" ]]; then
    fail "split multivolume extraction hash mismatch"
fi

log "checking split+solid multivolume extraction"
SPLIT_SOLID_SRC_DIR="$TMP_DIR/split_solid_src"
SPLIT_SOLID_OUT_DIR="$TMP_DIR/out_split_solid"
SPLIT_SOLID_ARCHIVE="$TMP_DIR/split_solid.rar"
mkdir -p "$SPLIT_SOLID_SRC_DIR/alpha"
for i in $(seq 1 500); do
    printf 'solid-split-line-%04d repeated pattern for dictionary reuse\n' "$i" >> "$SPLIT_SOLID_SRC_DIR/alpha/data.txt"
done
dd if=/dev/urandom of="$SPLIT_SOLID_SRC_DIR/alpha/random.bin" bs=1K count=256 status=none
(
    cd "$SPLIT_SOLID_SRC_DIR"
    "$RAR_BIN" a -idq -ma5 -m5 -s -v80k "$SPLIT_SOLID_ARCHIVE" ./alpha
)
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op"$SPLIT_SOLID_OUT_DIR" "$TMP_DIR/split_solid.part1.rar"
if [[ "$(dir_hash "$SPLIT_SOLID_SRC_DIR")" != "$(dir_hash "$SPLIT_SOLID_OUT_DIR")" ]]; then
    fail "split solid extraction hash mismatch"
fi

log "checking legacy .rar/.r00 chain handling"
LEGACY_OUT_DIR="$TMP_DIR/out_legacy"
cp "${SPLIT_PARTS[0]}" "$TMP_DIR/legacy_split.rar"
for i in "${!SPLIT_PARTS[@]}"; do
    if [[ "$i" -eq 0 ]]; then
        continue
    fi
    suffix="$(printf '.r%02d' "$((i - 1))")"
    cp "${SPLIT_PARTS[$i]}" "$TMP_DIR/legacy_split${suffix}"
done
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op"$LEGACY_OUT_DIR" "$TMP_DIR/legacy_split.rar"
if [[ "$(dir_hash "$SPLIT_SRC_DIR")" != "$(dir_hash "$LEGACY_OUT_DIR")" ]]; then
    fail "legacy volume chain extraction hash mismatch"
fi

log "checking missing split volume failure path"
MISSING_FIRST="$TMP_DIR/missing.$(basename "${SPLIT_PARTS[0]}")"
for part in "${SPLIT_PARTS[@]}"; do
    cp "$part" "$TMP_DIR/missing.$(basename "$part")"
done
rm -f "$TMP_DIR/missing.split_fast.part2.rar"
run_expect_exit 8 "$ROOT_DIR/raze" x -idq -o+ -op"$TMP_DIR/out_missing_split" "$MISSING_FIRST"

log "checking encrypted data archive extraction (-p)"
ENC_SRC_DIR="$TMP_DIR/enc_src"
ENC_OUT_DIR="$TMP_DIR/out_enc"
ENC_ARCHIVE="$TMP_DIR/encrypted_data.rar"
mkdir -p "$ENC_SRC_DIR/secret"
printf 'encrypted fixture text\n' > "$ENC_SRC_DIR/secret/a.txt"
dd if=/dev/urandom of="$ENC_SRC_DIR/secret/b.bin" bs=1K count=16 status=none
(
    cd "$ENC_SRC_DIR"
    "$RAR_BIN" a -idq -ma5 -m3 -s- -r -psecret "$ENC_ARCHIVE" ./secret
)
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -psecret -op"$ENC_OUT_DIR" "$ENC_ARCHIVE"
if [[ "$(dir_hash "$ENC_SRC_DIR")" != "$(dir_hash "$ENC_OUT_DIR")" ]]; then
    fail "encrypted data extraction hash mismatch"
fi
run_expect_exit 6 "$ROOT_DIR/raze" x -idq -o+ -pwrong -op"$TMP_DIR/out_enc_wrong" "$ENC_ARCHIVE"
run_expect_exit 2 "$ROOT_DIR/raze" x -idq -o+ -op"$TMP_DIR/out_enc_missing" "$ENC_ARCHIVE"
run_expect_exit 2 "$ROOT_DIR/raze" x -idq -o+ -p -op"$TMP_DIR/out_enc_prompt_missing" "$ENC_ARCHIVE"

log "checking encrypted headers archive extraction (-hp)"
HENC_OUT_DIR="$TMP_DIR/out_henc"
HENC_ARCHIVE="$TMP_DIR/encrypted_headers.rar"
(
    cd "$ENC_SRC_DIR"
    "$RAR_BIN" a -idq -ma5 -m3 -s- -r -hpsecret "$HENC_ARCHIVE" ./secret
)
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -psecret -op"$HENC_OUT_DIR" "$HENC_ARCHIVE"
if [[ "$(dir_hash "$ENC_SRC_DIR")" != "$(dir_hash "$HENC_OUT_DIR")" ]]; then
    fail "encrypted headers extraction hash mismatch"
fi
run_expect_exit 6 "$ROOT_DIR/raze" x -idq -o+ -pwrong -op"$TMP_DIR/out_henc_wrong" "$HENC_ARCHIVE"
run_expect_exit 2 "$ROOT_DIR/raze" x -idq -o+ -op"$TMP_DIR/out_henc_missing" "$HENC_ARCHIVE"
run_expect_exit 2 "$ROOT_DIR/raze" x -idq -o+ -p -op"$TMP_DIR/out_henc_prompt_missing" "$HENC_ARCHIVE"

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

log "checking metadata restore (mtime and mode)"
META_SRC_DIR="$TMP_DIR/meta_src"
META_OUT_DIR="$TMP_DIR/out_meta"
META_ARCHIVE="$TMP_DIR/meta_store.rar"
META_DIR_REL="meta_dir"
META_FILE_REL="$META_DIR_REL/meta_file.txt"
FILE_TS=1700000000
DIR_TS=1700000060
mkdir -p "$META_SRC_DIR/$META_DIR_REL"
printf 'metadata fixture\n' > "$META_SRC_DIR/$META_FILE_REL"
chmod 640 "$META_SRC_DIR/$META_FILE_REL"
chmod 750 "$META_SRC_DIR/$META_DIR_REL"
touch -m -d "@$FILE_TS" "$META_SRC_DIR/$META_FILE_REL"
touch -m -d "@$DIR_TS" "$META_SRC_DIR/$META_DIR_REL"
(
    cd "$META_SRC_DIR"
    "$RAR_BIN" a -idq -ma5 -m0 -s- -r "$META_ARCHIVE" .
)
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op"$META_OUT_DIR" "$META_ARCHIVE"
if ! cmp -s "$META_SRC_DIR/$META_FILE_REL" "$META_OUT_DIR/$META_FILE_REL"; then
    fail "metadata fixture content mismatch"
fi
if [[ "$(stat -c %a "$META_OUT_DIR/$META_FILE_REL")" != "640" ]]; then
    fail "metadata file mode mismatch"
fi
if [[ "$(stat -c %a "$META_OUT_DIR/$META_DIR_REL")" != "750" ]]; then
    fail "metadata directory mode mismatch"
fi
if [[ "$(stat -c %Y "$META_OUT_DIR/$META_FILE_REL")" -ne "$FILE_TS" ]]; then
    fail "metadata file mtime mismatch"
fi
if [[ "$(stat -c %Y "$META_OUT_DIR/$META_DIR_REL")" -ne "$DIR_TS" ]]; then
    fail "metadata directory mtime mismatch"
fi

log "checking bad archive detection with truncated input"
STORE_SIZE="$(stat -c%s "$ARCHIVE_STORE")"
if [[ "$STORE_SIZE" -le 256 ]]; then
    fail "store archive unexpectedly small for truncation test"
fi
dd if="$ARCHIVE_STORE" of="$TMP_DIR/truncated.rar" bs=1 count=$((STORE_SIZE / 2)) status=none
run_expect_exit 4 "$ROOT_DIR/raze" x -idq -op"$TMP_DIR/out_bad" "$TMP_DIR/truncated.rar"

log "checking bad compressed archive detection with truncated input"
FAST_SIZE="$(stat -c%s "$ARCHIVE_FAST")"
if [[ "$FAST_SIZE" -le 256 ]]; then
    fail "compressed archive unexpectedly small for truncation test"
fi
dd if="$ARCHIVE_FAST" of="$TMP_DIR/truncated_fast.rar" bs=1 count=$((FAST_SIZE / 2)) status=none
run_expect_exit_one_of 4 6 "$ROOT_DIR/raze" x -idq -op"$TMP_DIR/out_bad_fast" "$TMP_DIR/truncated_fast.rar"

log "all tests passed"
