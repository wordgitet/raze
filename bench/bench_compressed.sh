#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNS="${RUNS:-3}"
UNRAR_BIN="${UNRAR_BIN:-$(command -v unrar || true)}"
ARCHIVES=(
    "${ROOT_DIR}/corpus/local/archives/local_fast.rar"
    "${ROOT_DIR}/corpus/local/thematic/archives/thematic_fast.rar"
)

log() {
    printf '[bench-compressed] %s\n' "$*"
}

fail() {
    printf '[bench-compressed] error: %s\n' "$*" >&2
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

archive_source_dir() {
    local archive="$1"
    case "$(basename "$archive")" in
        local_fast.rar)
            printf '%s\n' "$ROOT_DIR/corpus/local/source"
            ;;
        thematic_fast.rar)
            printf '%s\n' "$ROOT_DIR/corpus/local/thematic/source"
            ;;
        *)
            return 1
            ;;
    esac
}

[[ -n "$UNRAR_BIN" ]] || fail "unrar binary not found. Set UNRAR_BIN."

"$ROOT_DIR/scripts/corpus_build_local.sh" >/dev/null
"$ROOT_DIR/scripts/corpus_build_thematic.sh" >/dev/null

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

for archive in "${ARCHIVES[@]}"; do
    source_dir="$(archive_source_dir "$archive")" || fail "unknown archive mapping: $archive"
    [[ -f "$archive" ]] || fail "archive not found: $archive"
    [[ -d "$source_dir" ]] || fail "source dir not found: $source_dir"

    bytes="$(du -sb "$source_dir" | awk '{print $1}')"
    [[ "$bytes" -gt 0 ]] || fail "source size is zero: $source_dir"

    raze_times_file="$TMP_DIR/raze_$(basename "$archive").txt"
    unrar_times_file="$TMP_DIR/unrar_$(basename "$archive").txt"

    log "running $RUNS runs for $(basename "$archive") [raze]"
    for _ in $(seq 1 "$RUNS"); do
        run_and_measure_seconds \
            "$TMP_DIR/raze_out" \
            "$ROOT_DIR/raze" x -idq -o+ -op"$TMP_DIR/raze_out" "$archive" \
            >> "$raze_times_file"
    done

    log "running $RUNS runs for $(basename "$archive") [unrar]"
    for _ in $(seq 1 "$RUNS"); do
        run_and_measure_seconds \
            "$TMP_DIR/unrar_out" \
            "$UNRAR_BIN" x -idq -o+ "$archive" "$TMP_DIR/unrar_out/" \
            >> "$unrar_times_file"
    done

    raze_median="$(sort -n "$raze_times_file" | median_from_stdin)"
    unrar_median="$(sort -n "$unrar_times_file" | median_from_stdin)"
    raze_mbps="$(awk -v b="$bytes" -v t="$raze_median" 'BEGIN { printf "%.2f", (b / 1048576.0) / t }')"
    unrar_mbps="$(awk -v b="$bytes" -v t="$unrar_median" 'BEGIN { printf "%.2f", (b / 1048576.0) / t }')"
    gap_pct="$(awk -v r="$raze_median" -v u="$unrar_median" 'BEGIN { printf "%.2f", ((r - u) / u) * 100.0 }')"

    log "$(basename "$archive"): raze=${raze_median}s (${raze_mbps} MiB/s), unrar=${unrar_median}s (${unrar_mbps} MiB/s), gap=${gap_pct}%"
done
