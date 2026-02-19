#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FUZZ_DIR="${1:-$ROOT_DIR/build/fuzz}"
RUN_SECS="${2:-30}"
SEED_ROOT="$ROOT_DIR/tests/fuzz/corpus"
WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/raze-fuzz-smoke.XXXXXX")"

cleanup() {
	rm -rf "$WORK_ROOT"
}
trap cleanup EXIT

if [[ -n "${ASAN_OPTIONS:-}" ]]; then
	export ASAN_OPTIONS="${ASAN_OPTIONS}:detect_leaks=0"
else
	export ASAN_OPTIONS="detect_leaks=0"
fi

log() {
	printf '[fuzz-smoke] %s\n' "$*"
}

fail() {
	printf '[fuzz-smoke] error: %s\n' "$*" >&2
	exit 1
}

run_target() {
	local target="$1"
	local corpus_name="$2"
	local seed_dir="$SEED_ROOT/$corpus_name"
	local work_dir="$WORK_ROOT/$corpus_name"
	local artifact_dir="$WORK_ROOT/artifacts/$target/"
	local bin="$FUZZ_DIR/$target"

	[[ -x "$bin" ]] || fail "missing fuzzer binary: $bin"
	[[ -d "$seed_dir" ]] || fail "missing seed corpus dir: $seed_dir"
	mkdir -p "$work_dir" "$artifact_dir"
	cp -a "$seed_dir/." "$work_dir/"
	log "running $target for ${RUN_SECS}s"
	"$bin" \
		-max_total_time="$RUN_SECS" \
		-artifact_prefix="$artifact_dir" \
		"$work_dir"
}

run_target "fuzz_vint" "vint"
run_target "fuzz_block_reader" "block_reader"
run_target "fuzz_file_header" "file_header"
run_target "fuzz_unpack_v50" "unpack_v50"

log "all smoke fuzz targets completed"
