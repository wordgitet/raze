#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCHIVE="${1:-$ROOT_DIR/corpus/local/archives/local_store.rar}"
SOURCE_DIR="${SOURCE_DIR:-$ROOT_DIR/corpus/local/source}"
RUNS="${RUNS:-3}"
UNRAR_BIN="${UNRAR_BIN:-$(command -v unrar || true)}"
UNRAR_THREADS="${UNRAR_THREADS:-1}"

log() {
    printf '[bench-store] %s\n' "$*"
}

fail() {
    printf '[bench-store] error: %s\n' "$*" >&2
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

if [[ -z "$UNRAR_BIN" ]]; then
    fail "unrar binary not found. Set UNRAR_BIN."
fi

if [[ ! -f "$ARCHIVE" || ! -d "$SOURCE_DIR" ]]; then
    log "local store corpus missing; generating it first"
    "$ROOT_DIR/scripts/corpus_build_local.sh"
fi

[[ -f "$ARCHIVE" ]] || fail "archive not found: $ARCHIVE"
[[ -d "$SOURCE_DIR" ]] || fail "source dir not found: $SOURCE_DIR"

BYTES="$(du -sb "$SOURCE_DIR" | awk '{print $1}')"
[[ "$BYTES" -gt 0 ]] || fail "source corpus size is zero"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

RAZE_TIMES_FILE="$TMP_DIR/raze_times.txt"
UNRAR_TIMES_FILE="$TMP_DIR/unrar_times.txt"

log "running $RUNS benchmark runs for raze"
for i in $(seq 1 "$RUNS"); do
    run_and_measure_seconds "$TMP_DIR/raze_out" "$ROOT_DIR/raze" x -idq -o+ -op"$TMP_DIR/raze_out" "$ARCHIVE" >> "$RAZE_TIMES_FILE"
done

log "running $RUNS benchmark runs for unrar"
for i in $(seq 1 "$RUNS"); do
    run_and_measure_seconds "$TMP_DIR/unrar_out" "$UNRAR_BIN" x -idq -o+ -mt"$UNRAR_THREADS" "$ARCHIVE" "$TMP_DIR/unrar_out/" >> "$UNRAR_TIMES_FILE"
done

RAZE_MEDIAN="$(sort -n "$RAZE_TIMES_FILE" | median_from_stdin)"
UNRAR_MEDIAN="$(sort -n "$UNRAR_TIMES_FILE" | median_from_stdin)"

RAZE_MBPS="$(awk -v b="$BYTES" -v t="$RAZE_MEDIAN" 'BEGIN { printf "%.2f", (b / 1048576.0) / t }')"
UNRAR_MBPS="$(awk -v b="$BYTES" -v t="$UNRAR_MEDIAN" 'BEGIN { printf "%.2f", (b / 1048576.0) / t }')"
GAP_PCT="$(awk -v r="$RAZE_MEDIAN" -v u="$UNRAR_MEDIAN" 'BEGIN { printf "%.2f", ((r - u) / u) * 100.0 }')"

log "raze median:  ${RAZE_MEDIAN}s (${RAZE_MBPS} MiB/s)"
log "unrar median: ${UNRAR_MEDIAN}s (${UNRAR_MBPS} MiB/s)"
log "time gap vs unrar: ${GAP_PCT}%"

if awk -v g="$GAP_PCT" 'BEGIN { exit !(g > 10.0) }'; then
    fail "performance gate failed: raze is more than 10% slower than unrar"
fi

log "performance gate passed (<=10% slower than unrar)"
