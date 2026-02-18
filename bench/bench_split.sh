#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNS="${RUNS:-3}"
UNRAR_BIN="${UNRAR_BIN:-$(command -v unrar || true)}"
RAR_BIN="${RAR_BIN:-$(command -v rar || true)}"

log() {
    printf '[bench-split] %s\n' "$*"
}

fail() {
    printf '[bench-split] error: %s\n' "$*" >&2
    exit 1
}

median_from_stdin() {
    awk '
        { values[++count] = $1 }
        END {
            if (count == 0) {
                print "0"
                exit
            }
            if (count % 2 == 1) {
                print values[(count + 1) / 2]
            } else {
                print (values[count / 2] + values[(count / 2) + 1]) / 2
            }
        }
    '
}

run_and_measure_seconds() {
    local out_dir="$1"
    shift
    local start_ns end_ns
    rm -rf "$out_dir"
    mkdir -p "$out_dir"
    start_ns="$(date +%s%N)"
    "$@" >/dev/null 2>&1
    end_ns="$(date +%s%N)"
    awk -v s="$start_ns" -v e="$end_ns" 'BEGIN { printf "%.6f\n", (e - s) / 1000000000.0 }'
}

[[ -n "$UNRAR_BIN" ]] || fail "unrar binary not found. Set UNRAR_BIN."
[[ -n "$RAR_BIN" ]] || fail "rar binary not found. Set RAR_BIN."

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

SRC_DIR="$TMP_DIR/split_src"
ARCHIVE_BASE="$TMP_DIR/split_bench.rar"
PART1="$TMP_DIR/split_bench.part1.rar"

mkdir -p "$SRC_DIR/data"
dd if=/dev/urandom of="$SRC_DIR/data/blob.bin" bs=1K count=1024 status=none
for i in $(seq 1 4000); do
    printf 'split-bench-line-%05d repeated pattern payload\n' "$i" >> "$SRC_DIR/data/text.txt"
done
(
    cd "$SRC_DIR"
    "$RAR_BIN" a -idq -ma5 -m1 -s- -v200k "$ARCHIVE_BASE" ./data
)

[[ -f "$PART1" ]] || fail "expected first volume not found: $PART1"
bytes="$(du -sb "$SRC_DIR" | awk '{print $1}')"
[[ "$bytes" -gt 0 ]] || fail "source size is zero"

raze_times_file="$TMP_DIR/raze_times.txt"
unrar_times_file="$TMP_DIR/unrar_times.txt"

log "running $RUNS runs [raze]"
for _ in $(seq 1 "$RUNS"); do
    run_and_measure_seconds \
        "$TMP_DIR/raze_out" \
        "$ROOT_DIR/raze" x -idq -o+ -op"$TMP_DIR/raze_out" "$PART1" \
        >> "$raze_times_file"
done

log "running $RUNS runs [unrar]"
for _ in $(seq 1 "$RUNS"); do
    run_and_measure_seconds \
        "$TMP_DIR/unrar_out" \
        "$UNRAR_BIN" x -idq -o+ "$PART1" "$TMP_DIR/unrar_out/" \
        >> "$unrar_times_file"
done

raze_median="$(sort -n "$raze_times_file" | median_from_stdin)"
unrar_median="$(sort -n "$unrar_times_file" | median_from_stdin)"
raze_mbps="$(awk -v b="$bytes" -v t="$raze_median" 'BEGIN { printf "%.2f", (b / 1048576.0) / t }')"
unrar_mbps="$(awk -v b="$bytes" -v t="$unrar_median" 'BEGIN { printf "%.2f", (b / 1048576.0) / t }')"
gap_pct="$(awk -v r="$raze_median" -v u="$unrar_median" 'BEGIN { printf "%.2f", ((r - u) / u) * 100.0 }')"

log "raze=${raze_median}s (${raze_mbps} MiB/s), unrar=${unrar_median}s (${unrar_mbps} MiB/s), gap=${gap_pct}%"
