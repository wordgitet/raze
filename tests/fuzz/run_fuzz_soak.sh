#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FUZZ_DIR="${1:-$ROOT_DIR/build/fuzz}"
RUN_SECS="${2:-300}"
SEED_ROOT="$ROOT_DIR/tests/fuzz/corpus"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT_ROOT="${RAZE_FUZZ_OUT:-$ROOT_DIR/build/fuzz-soak}/$STAMP"
WORK_ROOT="$OUT_ROOT/work"
ARTIFACT_ROOT="$OUT_ROOT/artifacts"

if [[ -n "${ASAN_OPTIONS:-}" ]]; then
	export ASAN_OPTIONS="${ASAN_OPTIONS}:detect_leaks=0"
else
	export ASAN_OPTIONS="detect_leaks=0"
fi

log() {
	printf '[fuzz-soak] %s\n' "$*"
}

fail() {
	printf '[fuzz-soak] error: %s\n' "$*" >&2
	exit 1
}

run_target() {
	local target="$1"
	local corpus_name="$2"
	local seed_dir="$SEED_ROOT/$corpus_name"
	local work_dir="$WORK_ROOT/$corpus_name"
	local artifact_dir="$ARTIFACT_ROOT/$target/"
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

mkdir -p "$WORK_ROOT" "$ARTIFACT_ROOT"
log "output directory: $OUT_ROOT"
log "fuzzer binaries: $FUZZ_DIR"

run_target "fuzz_vint" "vint"
run_target "fuzz_block_reader" "block_reader"
run_target "fuzz_file_header" "file_header"
run_target "fuzz_unpack_v50" "unpack_v50"

log "all soak fuzz targets completed"
log "artifacts kept in: $ARTIFACT_ROOT"
