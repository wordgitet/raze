#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXP_ROOT="$ROOT_DIR/corpus/local/expanded"
SOURCE_DIR="$EXP_ROOT/source"
ARCHIVE_DIR="$EXP_ROOT/archives"
CORRUPT_DIR="$EXP_ROOT/corrupt"

ARCHIVE_STORE="$ARCHIVE_DIR/expanded_store.rar"
ARCHIVE_FAST="$ARCHIVE_DIR/expanded_fast.rar"
ARCHIVE_SOLID="$ARCHIVE_DIR/expanded_best_solid.rar"
ARCHIVE_FAST_HTB="$ARCHIVE_DIR/expanded_fast_htb.rar"
ARCHIVE_BEST_HTB="$ARCHIVE_DIR/expanded_best_htb.rar"
ARCHIVE_ENC="$ARCHIVE_DIR/expanded_best_encrypted.rar"
ARCHIVE_HENC="$ARCHIVE_DIR/expanded_best_headers_encrypted.rar"

CORRUPT_TRUNCATED="$CORRUPT_DIR/expanded_fast_truncated.rar"
CORRUPT_BEST_HTB="$CORRUPT_DIR/expanded_best_htb_bitflip.rar"
CORRUPT_ENC_HTB="$CORRUPT_DIR/expanded_best_encrypted_htb_bitflip.rar"
ARCHIVE_FAST_SPLIT_P1=""
ARCHIVE_SOLID_SPLIT_P1=""

log() {
	printf '[test-expanded] %s\n' "$*"
}

FAILURES=0
LAST_EXPECT_OK=1

fatal() {
	printf '[test-expanded] error: %s\n' "$*" >&2
	exit 1
}

fail() {
	printf '[test-expanded] error: %s\n' "$*" >&2
	FAILURES=$((FAILURES + 1))
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
		LAST_EXPECT_OK=0
		return 0
	fi
	LAST_EXPECT_OK=1
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
		LAST_EXPECT_OK=0
		return 0
	fi
	LAST_EXPECT_OK=1
}

dir_hash() {
	local dir="$1"

	(
		cd "$dir"
		find . -type f -print0 | sort -z | xargs -0 sha256sum
	) | sha256sum | awk '{print $1}'
}

extract_and_compare_hash() {
	local label="$1"
	local archive="$2"
	local out_dir="$3"
	shift 3

	log "extracting $label"
	run_expect_exit 0 "$ROOT_DIR/raze" x -idq -o+ "$@" -op "$out_dir" "$archive"
	if [[ "$LAST_EXPECT_OK" -ne 1 ]]; then
		return
	fi
	if [[ "$SOURCE_HASH" != "$(dir_hash "$out_dir")" ]]; then
		fail "$label extraction hash mismatch"
	fi
}

log "ensuring expanded corpus exists"
"$ROOT_DIR/scripts/corpus_build_expanded.sh"

[[ -d "$SOURCE_DIR" ]] || fatal "missing $SOURCE_DIR"
[[ -f "$ARCHIVE_STORE" ]] || fatal "missing $ARCHIVE_STORE"
[[ -f "$ARCHIVE_FAST" ]] || fatal "missing $ARCHIVE_FAST"
[[ -f "$ARCHIVE_SOLID" ]] || fatal "missing $ARCHIVE_SOLID"
[[ -f "$ARCHIVE_FAST_HTB" ]] || fatal "missing $ARCHIVE_FAST_HTB"
[[ -f "$ARCHIVE_BEST_HTB" ]] || fatal "missing $ARCHIVE_BEST_HTB"
[[ -f "$ARCHIVE_ENC" ]] || fatal "missing $ARCHIVE_ENC"
[[ -f "$ARCHIVE_HENC" ]] || fatal "missing $ARCHIVE_HENC"
[[ -f "$CORRUPT_TRUNCATED" ]] || fatal "missing $CORRUPT_TRUNCATED"
[[ -f "$CORRUPT_BEST_HTB" ]] || fatal "missing $CORRUPT_BEST_HTB"
[[ -f "$CORRUPT_ENC_HTB" ]] || fatal "missing $CORRUPT_ENC_HTB"

ARCHIVE_FAST_SPLIT_P1="$(find "$ARCHIVE_DIR" -maxdepth 1 -type f -name 'expanded_fast_split*.part01.rar' | sort | head -n 1)"
ARCHIVE_SOLID_SPLIT_P1="$(find "$ARCHIVE_DIR" -maxdepth 1 -type f -name 'expanded_best_solid_split*.part01.rar' | sort | head -n 1)"
[[ -n "$ARCHIVE_FAST_SPLIT_P1" && -f "$ARCHIVE_FAST_SPLIT_P1" ]] || fatal "missing expanded fast split part01 archive"
[[ -n "$ARCHIVE_SOLID_SPLIT_P1" && -f "$ARCHIVE_SOLID_SPLIT_P1" ]] || fatal "missing expanded solid split part01 archive"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
SOURCE_HASH="$(dir_hash "$SOURCE_DIR")"

log "checking happy-path extraction for expanded store/fast/solid"
extract_and_compare_hash "expanded_store" "$ARCHIVE_STORE" "$TMP_DIR/out_store"
extract_and_compare_hash "expanded_fast" "$ARCHIVE_FAST" "$TMP_DIR/out_fast"
extract_and_compare_hash "expanded_best_solid" "$ARCHIVE_SOLID" "$TMP_DIR/out_solid"

log "checking encrypted extraction paths"
extract_and_compare_hash "expanded_best_encrypted" "$ARCHIVE_ENC" "$TMP_DIR/out_enc" -psecret
run_expect_exit 6 "$ROOT_DIR/raze" x -idq -o+ -pwrong -op "$TMP_DIR/out_enc_wrong" "$ARCHIVE_ENC"
extract_and_compare_hash "expanded_best_headers_encrypted" "$ARCHIVE_HENC" "$TMP_DIR/out_henc" -psecret

log "checking BLAKE integrity + technical list metadata"
extract_and_compare_hash "expanded_fast_htb" "$ARCHIVE_FAST_HTB" "$TMP_DIR/out_fast_htb"
extract_and_compare_hash "expanded_best_htb" "$ARCHIVE_BEST_HTB" "$TMP_DIR/out_best_htb"
run_expect_exit 0 "$ROOT_DIR/raze" lt "$ARCHIVE_FAST_HTB" > "$TMP_DIR/list_fast_htb.txt"
if [[ "$LAST_EXPECT_OK" -eq 1 ]] &&
   ! grep -Fq "hash_type=blake2sp" "$TMP_DIR/list_fast_htb.txt"; then
	fail "technical list missing blake2sp for expanded_fast_htb"
fi
run_expect_exit 0 "$ROOT_DIR/raze" lt "$ARCHIVE_BEST_HTB" > "$TMP_DIR/list_best_htb.txt"
if [[ "$LAST_EXPECT_OK" -eq 1 ]] &&
   ! grep -Fq "hash_type=blake2sp" "$TMP_DIR/list_best_htb.txt"; then
	fail "technical list missing blake2sp for expanded_best_htb"
fi

log "checking split extraction flows"
extract_and_compare_hash "expanded_fast_split.part1" "$ARCHIVE_FAST_SPLIT_P1" "$TMP_DIR/out_fast_split"
extract_and_compare_hash "expanded_best_solid_split.part1" "$ARCHIVE_SOLID_SPLIT_P1" "$TMP_DIR/out_solid_split"

SPLIT_MISSING_DIR="$TMP_DIR/split_missing"
SPLIT_PREFIX="${ARCHIVE_FAST_SPLIT_P1%part01.rar}"
mkdir -p "$SPLIT_MISSING_DIR"
cp "${SPLIT_PREFIX}"part*.rar "$SPLIT_MISSING_DIR"/
rm -f "$SPLIT_MISSING_DIR/$(basename "${SPLIT_PREFIX}")part02.rar"
run_expect_exit 8 "$ROOT_DIR/raze" x -idq -o+ -op "$TMP_DIR/out_split_missing" \
	"$SPLIT_MISSING_DIR/$(basename "${SPLIT_PREFIX}")part01.rar"

log "checking corruption regressions"
run_expect_exit 4 "$ROOT_DIR/raze" x -idq -o+ -op "$TMP_DIR/out_truncated" "$CORRUPT_TRUNCATED"
run_expect_exit_one_of 4 6 "$ROOT_DIR/raze" x -idq -o+ -op "$TMP_DIR/out_best_htb_corrupt" "$CORRUPT_BEST_HTB"
run_expect_exit_one_of 4 6 "$ROOT_DIR/raze" x -idq -o+ -psecret -op "$TMP_DIR/out_enc_htb_corrupt" "$CORRUPT_ENC_HTB"

if [[ "$FAILURES" -ne 0 ]]; then
	fatal "$FAILURES expanded check(s) failed"
fi

log "all expanded corpus checks passed"
