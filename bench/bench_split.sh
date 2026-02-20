#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNS="${RUNS:-7}"
UNRAR_BIN="${UNRAR_BIN:-$("$ROOT_DIR"/scripts/find_unrar.sh || true)}"
UNRAR_THREADS="${UNRAR_THREADS:-1}"
RAR_BIN="${RAR_BIN:-$("$ROOT_DIR"/scripts/find_rar.sh || true)}"
TARGET_GAP_PCT="${TARGET_GAP_PCT:-10}"

log() {
    printf '[bench-split] %s\n' "$*"
}

warn() {
    printf '[bench-split] warning: %s\n' "$*" >&2
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

percentile_from_file() {
    local file="$1"
    local numerator="$2"
    local denominator="$3"
    awk -v nmr="$numerator" -v dnm="$denominator" '
        { values[++count] = $1 }
        END {
            if (count == 0) {
                print "0"
                exit
            }
            idx = int((count * nmr + dnm - 1) / dnm)
            if (idx < 1) {
                idx = 1
            } else if (idx > count) {
                idx = count
            }
            print values[idx]
        }
    ' "$file"
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
raze_sorted_file="$TMP_DIR/raze_sorted.txt"
unrar_sorted_file="$TMP_DIR/unrar_sorted.txt"

log "warmup [raze]"
run_and_measure_seconds \
    "$TMP_DIR/raze_warmup" \
    "$ROOT_DIR/raze" x -idq -o+ -op"$TMP_DIR/raze_warmup" "$PART1" \
    >/dev/null

log "warmup [unrar]"
run_and_measure_seconds \
    "$TMP_DIR/unrar_warmup" \
    "$UNRAR_BIN" x -idq -o+ -mt"$UNRAR_THREADS" "$PART1" "$TMP_DIR/unrar_warmup/" \
    >/dev/null

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
        "$UNRAR_BIN" x -idq -o+ -mt"$UNRAR_THREADS" "$PART1" "$TMP_DIR/unrar_out/" \
        >> "$unrar_times_file"
done

sort -n "$raze_times_file" > "$raze_sorted_file"
sort -n "$unrar_times_file" > "$unrar_sorted_file"
raze_p50="$(median_from_stdin < "$raze_sorted_file")"
unrar_p50="$(median_from_stdin < "$unrar_sorted_file")"
raze_p90="$(percentile_from_file "$raze_sorted_file" 9 10)"
unrar_p90="$(percentile_from_file "$unrar_sorted_file" 9 10)"
raze_mbps="$(awk -v b="$bytes" -v t="$raze_p50" 'BEGIN { printf "%.2f", (b / 1048576.0) / t }')"
unrar_mbps="$(awk -v b="$bytes" -v t="$unrar_p50" 'BEGIN { printf "%.2f", (b / 1048576.0) / t }')"
gap_pct="$(awk -v r="$raze_p50" -v u="$unrar_p50" 'BEGIN { printf "%.2f", ((r - u) / u) * 100.0 }')"

log "raze p50=${raze_p50}s p90=${raze_p90}s (${raze_mbps} MiB/s)"
log "unrar p50=${unrar_p50}s p90=${unrar_p90}s (${unrar_mbps} MiB/s)"
log "time gap vs unrar: ${gap_pct}%"
if awk -v g="$gap_pct" -v t="$TARGET_GAP_PCT" 'BEGIN { exit !(g > t) }'; then
    warn "outside target (>${TARGET_GAP_PCT}% slower than unrar)"
fi
