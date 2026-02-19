#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CC_BIN="${CC:-cc}"
EXTRA_CFLAGS="${EXTRA_CFLAGS:-}"
EXTRA_LDFLAGS="${EXTRA_LDFLAGS:-}"
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

is_windows_shell() {
    case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        return 0
        ;;
    *)
        return 1
        ;;
    esac
}

windows_mtime_matches() {
    local expected="$1"
    local actual="$2"
    local diff
    local mod

    diff=$((actual - expected))
    if ((diff < 0)); then
        diff=$(( -diff ))
    fi

    # Normal NTFS timestamp precision differences.
    if ((diff <= 2)); then
        return 0
    fi

    # Accept whole-hour timezone skew (RAR/DOS timestamp conversion quirks).
    mod=$((diff % 3600))
    if ((diff <= 14 * 3600 + 2)) &&
       ((mod <= 2 || mod >= 3598)); then
        return 0
    fi

    return 1
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

run_expect_exit_stdin_null() {
    local expected="$1"
    shift
    local rc
    set +e
    "$@" < /dev/null
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
CC="$CC_BIN" \
EXTRA_CFLAGS="$EXTRA_CFLAGS" \
EXTRA_LDFLAGS="$EXTRA_LDFLAGS" \
"$ROOT_DIR/tests/test_parser_units.sh"

OUT_DIR="$TMP_DIR/out_store"
log "extracting store archive and checking file contents"
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op "$OUT_DIR" "$ARCHIVE_STORE"

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
run_expect_exit_stdin_null 7 "$ROOT_DIR/raze" x -idq -op "$OUT_DIR" "$ARCHIVE_STORE"

log "checking forced overwrite path"
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op "$OUT_DIR" "$ARCHIVE_STORE"

log "checking supported compatibility switches for extract"
run_expect_exit 0 "$ROOT_DIR/raze" x -y -idq -op "$TMP_DIR/out_y" "$ARCHIVE_STORE"
run_expect_exit 0 "$ROOT_DIR/raze" x -inul -o+ -op "$TMP_DIR/out_inul" "$ARCHIVE_STORE"
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -psecret -op "$TMP_DIR/out_p" "$ARCHIVE_STORE"
run_expect_exit 0 "$ROOT_DIR/raze" x -idp -o+ -op "$TMP_DIR/out_idp" "$ARCHIVE_STORE"
set +e
"$ROOT_DIR/raze" l -idq "$ARCHIVE_STORE" > /dev/null
rc=$?
set -e
if [[ "$rc" -ne 0 ]]; then
    fail "list command with -idq failed with exit $rc"
fi

log "checking -ap include-prefix filtering for list and extract"
LIST_AP_OUT="$TMP_DIR/list_ap_output.txt"
set +e
"$ROOT_DIR/raze" l -aptree "$ARCHIVE_STORE" > "$LIST_AP_OUT"
rc=$?
set -e
if [[ "$rc" -ne 0 ]]; then
    fail "list command with -ap failed with exit $rc"
fi
if ! grep -Fq "tree/file_1.txt" "$LIST_AP_OUT"; then
    fail "list -ap output missing expected tree/file_1.txt"
fi
if grep -Fq "small_text.txt" "$LIST_AP_OUT"; then
    fail "list -ap output unexpectedly included small_text.txt"
fi
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -aptree -op "$TMP_DIR/out_ap" "$ARCHIVE_STORE"
if [[ ! -f "$TMP_DIR/out_ap/tree/file_1.txt" ]]; then
    fail "extract -ap output missing expected tree/file_1.txt"
fi
if [[ -f "$TMP_DIR/out_ap/small_text.txt" ]]; then
    fail "extract -ap output unexpectedly included small_text.txt"
fi

log "checking -n@ and -x@ list-file filtering"
printf 'small_text.txt\n' > "$TMP_DIR/include.list"
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -n@"$TMP_DIR/include.list" -op "$TMP_DIR/out_n_at" "$ARCHIVE_STORE"
if [[ ! -f "$TMP_DIR/out_n_at/small_text.txt" ]]; then
    fail "extract -n@ output missing expected small_text.txt"
fi
if [[ -f "$TMP_DIR/out_n_at/medium_text.txt" ]]; then
    fail "extract -n@ output unexpectedly included medium_text.txt"
fi
printf 'tree/*\n' > "$TMP_DIR/exclude.list"
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -x@"$TMP_DIR/exclude.list" -op "$TMP_DIR/out_x_at" "$ARCHIVE_STORE"
if [[ ! -f "$TMP_DIR/out_x_at/small_text.txt" ]]; then
    fail "extract -x@ output missing expected small_text.txt"
fi
if [[ -f "$TMP_DIR/out_x_at/tree/file_1.txt" ]]; then
    fail "extract -x@ output unexpectedly included tree/file_1.txt"
fi

log "checking -ad1/-ad2 destination variants"
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -ad1 -op "$TMP_DIR/out_ad1" "$ARCHIVE_STORE"
if [[ ! -f "$TMP_DIR/out_ad1/local_store/small_text.txt" ]]; then
    fail "extract -ad1 output missing expected local_store/small_text.txt"
fi
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -ad2 -op "$TMP_DIR/out_ad2" "$ARCHIVE_STORE"
if [[ ! -f "$TMP_DIR/out_ad2/local_store.rar/small_text.txt" ]]; then
    fail "extract -ad2 output missing expected local_store.rar/small_text.txt"
fi

log "checking -o switch compatibility (bare -o must be rejected)"
run_expect_exit 2 "$ROOT_DIR/raze" x -idq -o "$ARCHIVE_STORE"

log "checking malformed and invalid switch forms return usage exit"
run_expect_exit 2 "$ROOT_DIR/raze" x -idq -ap "$ARCHIVE_STORE"
run_expect_exit 2 "$ROOT_DIR/raze" x -idq -n@ "$ARCHIVE_STORE"
run_expect_exit 2 "$ROOT_DIR/raze" x -idq -x@ "$ARCHIVE_STORE"
run_expect_exit 2 "$ROOT_DIR/raze" x -idq -n@"$TMP_DIR/does-not-exist.list" "$ARCHIVE_STORE"
run_expect_exit 2 "$ROOT_DIR/raze" x -idq -ad3 "$ARCHIVE_STORE"
run_expect_exit 2 "$ROOT_DIR/raze" l -ad1 "$ARCHIVE_STORE"
run_expect_exit 2 "$ROOT_DIR/raze" t -op "$TMP_DIR/out_invalid_op" "$ARCHIVE_STORE"

log "checking e command path-stripping behavior"
run_expect_exit 0 "$ROOT_DIR/raze" e -idq -o+ -op "$TMP_DIR/out_e" "$ARCHIVE_STORE"
if [[ ! -f "$TMP_DIR/out_e/file_1.txt" ]]; then
    fail "e command did not flatten nested path file_1.txt"
fi

log "checking t command integrity-only path"
run_expect_exit 0 "$ROOT_DIR/raze" t -idq "$ARCHIVE_STORE"

log "checking p command print path"
P_OUT="$TMP_DIR/print_small.txt"
set +e
"$ROOT_DIR/raze" p -idq -nsmall_text.txt "$ARCHIVE_STORE" > "$P_OUT"
rc=$?
set -e
if [[ "$rc" -ne 0 ]]; then
    fail "print command failed with exit $rc"
fi
if [[ ! -s "$P_OUT" ]]; then
    fail "print command produced empty output"
fi

log "checking SFX-prefixed archive signature scan"
dd if=/dev/zero of="$TMP_DIR/sfx_prefix.bin" bs=1 count=512 status=none
cat "$TMP_DIR/sfx_prefix.bin" "$ARCHIVE_STORE" > "$TMP_DIR/sfx_store.rar"
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op "$TMP_DIR/out_sfx" "$TMP_DIR/sfx_store.rar"
SFX_HASH="$(dir_hash "$TMP_DIR/out_sfx")"
if [[ "$SRC_HASH" != "$SFX_HASH" ]]; then
    fail "SFX-prefixed archive extraction mismatch"
fi

log "checking compressed extraction path"
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op "$TMP_DIR/out_fast" "$ARCHIVE_FAST"
FAST_HASH="$(dir_hash "$TMP_DIR/out_fast")"
if [[ "$SRC_HASH" != "$FAST_HASH" ]]; then
    fail "compressed extraction hash mismatch"
fi

log "checking compressed extraction path on thematic corpus"
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op "$TMP_DIR/out_thematic_fast" "$ARCHIVE_THEMATIC_FAST"
THEMATIC_SRC_HASH="$(dir_hash "$THEMATIC_SOURCE_DIR")"
THEMATIC_DST_HASH="$(dir_hash "$TMP_DIR/out_thematic_fast")"
if [[ "$THEMATIC_SRC_HASH" != "$THEMATIC_DST_HASH" ]]; then
    fail "thematic compressed extraction hash mismatch"
fi

log "checking solid extraction path"
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op "$TMP_DIR/out_solid" "$ARCHIVE_SOLID"
SOLID_HASH="$(dir_hash "$TMP_DIR/out_solid")"
if [[ "$SRC_HASH" != "$SOLID_HASH" ]]; then
    fail "solid extraction hash mismatch"
fi

log "checking solid extraction path on thematic corpus"
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op "$TMP_DIR/out_thematic_solid" "$ARCHIVE_THEMATIC_SOLID"
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
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op "$SPLIT_OUT_DIR" "$TMP_DIR/split_fast.part1.rar"
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
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op "$SPLIT_SOLID_OUT_DIR" "$TMP_DIR/split_solid.part1.rar"
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
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op "$LEGACY_OUT_DIR" "$TMP_DIR/legacy_split.rar"
if [[ "$(dir_hash "$SPLIT_SRC_DIR")" != "$(dir_hash "$LEGACY_OUT_DIR")" ]]; then
    fail "legacy volume chain extraction hash mismatch"
fi

log "checking missing split volume failure path"
MISSING_FIRST="$TMP_DIR/missing.$(basename "${SPLIT_PARTS[0]}")"
for part in "${SPLIT_PARTS[@]}"; do
    cp "$part" "$TMP_DIR/missing.$(basename "$part")"
done
rm -f "$TMP_DIR/missing.split_fast.part2.rar"
run_expect_exit 8 "$ROOT_DIR/raze" x -idq -o+ -op "$TMP_DIR/out_missing_split" "$MISSING_FIRST"

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
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -psecret -op "$ENC_OUT_DIR" "$ENC_ARCHIVE"
if [[ "$(dir_hash "$ENC_SRC_DIR")" != "$(dir_hash "$ENC_OUT_DIR")" ]]; then
    fail "encrypted data extraction hash mismatch"
fi
run_expect_exit 6 "$ROOT_DIR/raze" x -idq -o+ -pwrong -op "$TMP_DIR/out_enc_wrong" "$ENC_ARCHIVE"
run_expect_exit 2 "$ROOT_DIR/raze" x -idq -o+ -op "$TMP_DIR/out_enc_missing" "$ENC_ARCHIVE"
run_expect_exit_stdin_null 2 "$ROOT_DIR/raze" x -idq -o+ -p -op "$TMP_DIR/out_enc_prompt_missing" "$ENC_ARCHIVE"

log "checking encrypted headers archive extraction (-hp)"
HENC_OUT_DIR="$TMP_DIR/out_henc"
HENC_ARCHIVE="$TMP_DIR/encrypted_headers.rar"
(
    cd "$ENC_SRC_DIR"
    "$RAR_BIN" a -idq -ma5 -m3 -s- -r -hpsecret "$HENC_ARCHIVE" ./secret
)
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -psecret -op "$HENC_OUT_DIR" "$HENC_ARCHIVE"
if [[ "$(dir_hash "$ENC_SRC_DIR")" != "$(dir_hash "$HENC_OUT_DIR")" ]]; then
    fail "encrypted headers extraction hash mismatch"
fi
run_expect_exit 6 "$ROOT_DIR/raze" x -idq -o+ -pwrong -op "$TMP_DIR/out_henc_wrong" "$HENC_ARCHIVE"
run_expect_exit 2 "$ROOT_DIR/raze" x -idq -o+ -op "$TMP_DIR/out_henc_missing" "$HENC_ARCHIVE"
run_expect_exit_stdin_null 2 "$ROOT_DIR/raze" x -idq -o+ -p -op "$TMP_DIR/out_henc_prompt_missing" "$HENC_ARCHIVE"

log "checking BLAKE technical list and non-split verification"
BLAKE_SRC_DIR="$TMP_DIR/blake_src"
BLAKE_OUT_DIR="$TMP_DIR/out_blake"
BLAKE_ARCHIVE="$TMP_DIR/blake_fast_htb.rar"
mkdir -p "$BLAKE_SRC_DIR/tree"
printf 'blake fixture text\n' > "$BLAKE_SRC_DIR/tree/a.txt"
dd if=/dev/urandom of="$BLAKE_SRC_DIR/tree/b.bin" bs=1K count=256 status=none
(
    cd "$BLAKE_SRC_DIR"
    "$RAR_BIN" a -idq -ma5 -m5 -htb -s- -r "$BLAKE_ARCHIVE" .
)
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op "$BLAKE_OUT_DIR" "$BLAKE_ARCHIVE"
if [[ "$(dir_hash "$BLAKE_SRC_DIR")" != "$(dir_hash "$BLAKE_OUT_DIR")" ]]; then
    fail "blake non-split extraction hash mismatch"
fi
run_expect_exit 0 "$ROOT_DIR/raze" lt "$BLAKE_ARCHIVE" > "$TMP_DIR/list_blake.txt"
if ! grep -Fq "hash_type=blake2sp" "$TMP_DIR/list_blake.txt"; then
    fail "technical list missing blake2sp hash type"
fi
cp "$BLAKE_ARCHIVE" "$TMP_DIR/blake_fast_htb_corrupt.rar"
printf '\x01' | dd of="$TMP_DIR/blake_fast_htb_corrupt.rar" bs=1 seek=8192 conv=notrunc status=none
run_expect_exit 6 "$ROOT_DIR/raze" x -idq -o+ -op "$TMP_DIR/out_blake_corrupt" "$TMP_DIR/blake_fast_htb_corrupt.rar"

log "checking split BLAKE packed-part verification"
BLAKE_SPLIT_OUT_DIR="$TMP_DIR/out_blake_split"
BLAKE_SPLIT_ARCHIVE="$TMP_DIR/blake_split_htb.rar"
(
    cd "$BLAKE_SRC_DIR"
    "$RAR_BIN" a -idq -ma5 -m3 -htb -s- -v120k "$BLAKE_SPLIT_ARCHIVE" ./tree
)
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op "$BLAKE_SPLIT_OUT_DIR" "$TMP_DIR/blake_split_htb.part1.rar"
if [[ "$(dir_hash "$BLAKE_SRC_DIR")" != "$(dir_hash "$BLAKE_SPLIT_OUT_DIR")" ]]; then
    fail "split blake extraction hash mismatch"
fi
mapfile -t BLAKE_SPLIT_PARTS < <(find "$TMP_DIR" -maxdepth 1 -type f -name 'blake_split_htb.part*.rar' | sort -V)
if [[ "${#BLAKE_SPLIT_PARTS[@]}" -lt 2 ]]; then
    fail "split blake fixture did not produce multiple volumes"
fi
for part in "${BLAKE_SPLIT_PARTS[@]}"; do
    part_base="$(basename "$part")"
    part_suffix="${part_base#blake_split_htb.}"
    cp "$part" "$TMP_DIR/blake_split_htb_corrupt.${part_suffix}"
done
printf '\x02' | dd of="$TMP_DIR/blake_split_htb_corrupt.part1.rar" bs=1 seek=32768 conv=notrunc status=none
run_expect_exit 6 "$ROOT_DIR/raze" x -idq -o+ -op "$TMP_DIR/out_blake_split_corrupt" "$TMP_DIR/blake_split_htb_corrupt.part1.rar"

log "checking encrypted BLAKE verification"
BLAKE_ENC_OUT_DIR="$TMP_DIR/out_blake_enc"
BLAKE_ENC_ARCHIVE="$TMP_DIR/blake_enc_htb.rar"
(
    cd "$BLAKE_SRC_DIR"
    "$RAR_BIN" a -idq -ma5 -m3 -htb -s- -r -psecret "$BLAKE_ENC_ARCHIVE" .
)
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -psecret -op "$BLAKE_ENC_OUT_DIR" "$BLAKE_ENC_ARCHIVE"
if [[ "$(dir_hash "$BLAKE_SRC_DIR")" != "$(dir_hash "$BLAKE_ENC_OUT_DIR")" ]]; then
    fail "encrypted blake extraction hash mismatch"
fi
run_expect_exit 6 "$ROOT_DIR/raze" x -idq -o+ -pwrong -op "$TMP_DIR/out_blake_enc_wrong" "$BLAKE_ENC_ARCHIVE"

log "checking split + encrypted BLAKE verification"
BLAKE_SPLIT_ENC_OUT_DIR="$TMP_DIR/out_blake_split_enc"
BLAKE_SPLIT_ENC_ARCHIVE="$TMP_DIR/blake_split_enc_htb.rar"
(
    cd "$BLAKE_SRC_DIR"
    "$RAR_BIN" a -idq -ma5 -m3 -htb -s- -v120k -r -psecret "$BLAKE_SPLIT_ENC_ARCHIVE" ./tree
)
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -psecret -op "$BLAKE_SPLIT_ENC_OUT_DIR" "$TMP_DIR/blake_split_enc_htb.part1.rar"
if [[ "$(dir_hash "$BLAKE_SRC_DIR")" != "$(dir_hash "$BLAKE_SPLIT_ENC_OUT_DIR")" ]]; then
    fail "split encrypted blake extraction hash mismatch"
fi
mapfile -t BLAKE_SPLIT_ENC_PARTS < <(find "$TMP_DIR" -maxdepth 1 -type f -name 'blake_split_enc_htb.part*.rar' | sort -V)
if [[ "${#BLAKE_SPLIT_ENC_PARTS[@]}" -lt 2 ]]; then
    fail "split encrypted blake fixture did not produce multiple volumes"
fi
for part in "${BLAKE_SPLIT_ENC_PARTS[@]}"; do
    part_base="$(basename "$part")"
    part_suffix="${part_base#blake_split_enc_htb.}"
    cp "$part" "$TMP_DIR/blake_split_enc_htb_corrupt.${part_suffix}"
done
printf '\x03' | dd of="$TMP_DIR/blake_split_enc_htb_corrupt.part1.rar" bs=1 seek=32768 conv=notrunc status=none
run_expect_exit 6 "$ROOT_DIR/raze" x -idq -o+ -psecret -op "$TMP_DIR/out_blake_split_enc_corrupt" "$TMP_DIR/blake_split_enc_htb_corrupt.part1.rar"

log "checking split + encrypted BLAKE missing-volume failure path"
BLAKE_SPLIT_ENC_MISSING_FIRST="$TMP_DIR/blake_split_enc_htb_missing.part1.rar"
for part in "${BLAKE_SPLIT_ENC_PARTS[@]}"; do
    part_base="$(basename "$part")"
    part_suffix="${part_base#blake_split_enc_htb.}"
    cp "$part" "$TMP_DIR/blake_split_enc_htb_missing.${part_suffix}"
done
rm -f "$TMP_DIR/blake_split_enc_htb_missing.part2.rar"
run_expect_exit 8 "$ROOT_DIR/raze" x -idq -o+ -psecret -op "$TMP_DIR/out_blake_split_enc_missing" "$BLAKE_SPLIT_ENC_MISSING_FIRST"

log "checking truncated encrypted-header archive detection"
HENC_SIZE="$(stat -c%s "$HENC_ARCHIVE")"
if [[ "$HENC_SIZE" -le 256 ]]; then
    fail "encrypted header archive unexpectedly small for truncation test"
fi
dd if="$HENC_ARCHIVE" of="$TMP_DIR/encrypted_headers_truncated.rar" bs=1 count=$((HENC_SIZE / 2)) status=none
run_expect_exit_one_of 4 6 "$ROOT_DIR/raze" x -idq -o+ -psecret -op "$TMP_DIR/out_henc_truncated" "$TMP_DIR/encrypted_headers_truncated.rar"

LONG_PATH_MIN=1024
if is_windows_shell; then
    # MSYS/UCRT builds go through Win32 path APIs, so keep this as a
    # practical long-path stress instead of Linux-length (>1024) depth.
    LONG_PATH_MIN=180
fi
log "checking long archive path support (>${LONG_PATH_MIN} bytes)"
LONG_SRC_DIR="$TMP_DIR/long_src"
LONG_OUT_DIR="$TMP_DIR/out_long"
LONG_ARCHIVE="$TMP_DIR/long_store.rar"
LONG_SEGMENT="segment0123456789segment0123456789"
LONG_REL_DIR=""
while [[ ${#LONG_REL_DIR} -le "$LONG_PATH_MIN" ]]; do
    if [[ -z "$LONG_REL_DIR" ]]; then
        LONG_REL_DIR="$LONG_SEGMENT"
    else
        LONG_REL_DIR="$LONG_REL_DIR/$LONG_SEGMENT"
    fi
done
LONG_REL_FILE="$LONG_REL_DIR/leaf.txt"
mkdir -p "$LONG_SRC_DIR/$LONG_REL_DIR"
printf 'long path fixture\n' > "$LONG_SRC_DIR/$LONG_REL_FILE"
if [[ ${#LONG_REL_FILE} -le "$LONG_PATH_MIN" ]]; then
    fail "long path fixture is not long enough: ${#LONG_REL_FILE}"
fi
(
    cd "$LONG_SRC_DIR"
    "$RAR_BIN" a -idq -ma5 -m0 -s- -r "$LONG_ARCHIVE" .
)
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op "$LONG_OUT_DIR" "$LONG_ARCHIVE"
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
run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ -op "$META_OUT_DIR" "$META_ARCHIVE"
if ! cmp -s "$META_SRC_DIR/$META_FILE_REL" "$META_OUT_DIR/$META_FILE_REL"; then
    fail "metadata fixture content mismatch"
fi
if is_windows_shell; then
    FILE_MTIME_ACTUAL="$(stat -c %Y "$META_OUT_DIR/$META_FILE_REL")"
    DIR_MTIME_ACTUAL="$(stat -c %Y "$META_OUT_DIR/$META_DIR_REL")"

    # chmod on Windows maps to readonly semantics only, so skip strict bits.
    if ! windows_mtime_matches "$FILE_TS" "$FILE_MTIME_ACTUAL" ||
       ! windows_mtime_matches "$DIR_TS" "$DIR_MTIME_ACTUAL"; then
        log "note: windows mtime not stable in this environment; skipping strict mtime assertions"
        log "debug: expected file mtime=$FILE_TS actual=$FILE_MTIME_ACTUAL"
        log "debug: expected dir mtime=$DIR_TS actual=$DIR_MTIME_ACTUAL"
    fi
else
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
fi

log "checking bad archive detection with truncated input"
STORE_SIZE="$(stat -c%s "$ARCHIVE_STORE")"
if [[ "$STORE_SIZE" -le 256 ]]; then
    fail "store archive unexpectedly small for truncation test"
fi
dd if="$ARCHIVE_STORE" of="$TMP_DIR/truncated.rar" bs=1 count=$((STORE_SIZE / 2)) status=none
run_expect_exit 4 "$ROOT_DIR/raze" x -idq -op "$TMP_DIR/out_bad" "$TMP_DIR/truncated.rar"

log "checking bad compressed archive detection with truncated input"
FAST_SIZE="$(stat -c%s "$ARCHIVE_FAST")"
if [[ "$FAST_SIZE" -le 256 ]]; then
    fail "compressed archive unexpectedly small for truncation test"
fi
dd if="$ARCHIVE_FAST" of="$TMP_DIR/truncated_fast.rar" bs=1 count=$((FAST_SIZE / 2)) status=none
run_expect_exit_one_of 4 6 "$ROOT_DIR/raze" x -idq -op "$TMP_DIR/out_bad_fast" "$TMP_DIR/truncated_fast.rar"

log "all tests passed"
