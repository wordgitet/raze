#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNS="${RUNS:-7}"
UNRAR_BIN="${UNRAR_BIN:-$("$ROOT_DIR"/scripts/find_unrar.sh || true)}"
UNRAR_THREADS="${UNRAR_THREADS:-1}"
PASSWORD="${PASSWORD:-secret}"
TARGET_GAP_PCT="${TARGET_GAP_PCT:-10}"
ARCHIVE_DIR="$ROOT_DIR/corpus/local/expanded/archives"
SOURCE_DIR="$ROOT_DIR/corpus/local/expanded/source"
ENTRIES=(
	"expanded_store.rar:expanded-store:0"
	"expanded_fast.rar:expanded-fast:0"
	"expanded_best_solid.rar:expanded-best-solid:0"
	"expanded_best_encrypted.rar:expanded-best-encrypted:1"
)

log() {
	printf '[bench-expanded] %s\n' "$*"
}

warn() {
	printf '[bench-expanded] warning: %s\n' "$*" >&2
}

fail() {
	printf '[bench-expanded] error: %s\n' "$*" >&2
	exit 1
}

BENCH_CPU_CORE="${BENCH_CPU_CORE:-}"
USE_TASKSET=0
if [[ -n "$BENCH_CPU_CORE" ]]; then
	if command -v taskset >/dev/null 2>&1; then
		USE_TASKSET=1
		log "pinning benchmark commands to CPU core ${BENCH_CPU_CORE}"
	else
		warn "BENCH_CPU_CORE is set, but taskset is unavailable; running unpinned"
	fi
fi

run_with_affinity() {
	if [[ "$USE_TASKSET" -eq 1 ]]; then
		taskset -c "$BENCH_CPU_CORE" "$@"
	else
		"$@"
	fi
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
	run_with_affinity "$@" >/dev/null 2>&1
	end_ns="$(date +%s%N)"
	awk -v s="$start_ns" -v e="$end_ns" \
		'BEGIN { printf "%.6f\n", (e - s) / 1000000000.0 }'
}

[[ -n "$UNRAR_BIN" ]] || fail "unrar binary not found. Set UNRAR_BIN."

"$ROOT_DIR/scripts/corpus_build_expanded.sh" >/dev/null

[[ -d "$SOURCE_DIR" ]] || fail "source dir not found: $SOURCE_DIR"
bytes="$(du -sb "$SOURCE_DIR" | awk '{print $1}')"
[[ "$bytes" -gt 0 ]] || fail "source size is zero: $SOURCE_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

for entry in "${ENTRIES[@]}"; do
	IFS=':' read -r archive_name label needs_password <<< "$entry"
	archive="$ARCHIVE_DIR/$archive_name"

	[[ -f "$archive" ]] || fail "archive not found: $archive"
	raze_times_file="$TMP_DIR/raze_${label}.txt"
	unrar_times_file="$TMP_DIR/unrar_${label}.txt"
	raze_sorted_file="$TMP_DIR/raze_sorted_${label}.txt"
	unrar_sorted_file="$TMP_DIR/unrar_sorted_${label}.txt"

	log "warmup [$label] raze"
	if [[ "$needs_password" -eq 1 ]]; then
		run_and_measure_seconds \
			"$TMP_DIR/raze_warmup_${label}" \
			"$ROOT_DIR/raze" x -idq -o+ -p"$PASSWORD" \
			-op"$TMP_DIR/raze_warmup_${label}" "$archive" >/dev/null
	else
		run_and_measure_seconds \
			"$TMP_DIR/raze_warmup_${label}" \
			"$ROOT_DIR/raze" x -idq -o+ \
			-op"$TMP_DIR/raze_warmup_${label}" "$archive" >/dev/null
	fi

	log "warmup [$label] unrar"
	if [[ "$needs_password" -eq 1 ]]; then
		run_and_measure_seconds \
			"$TMP_DIR/unrar_warmup_${label}" \
			"$UNRAR_BIN" x -idq -o+ -mt"$UNRAR_THREADS" -p"$PASSWORD" \
			"$archive" "$TMP_DIR/unrar_warmup_${label}/" >/dev/null
	else
		run_and_measure_seconds \
			"$TMP_DIR/unrar_warmup_${label}" \
			"$UNRAR_BIN" x -idq -o+ -mt"$UNRAR_THREADS" \
			"$archive" "$TMP_DIR/unrar_warmup_${label}/" >/dev/null
	fi

	log "running $RUNS runs [$label] raze"
	for _ in $(seq 1 "$RUNS"); do
		if [[ "$needs_password" -eq 1 ]]; then
			run_and_measure_seconds \
				"$TMP_DIR/raze_out_${label}" \
				"$ROOT_DIR/raze" x -idq -o+ -p"$PASSWORD" \
				-op"$TMP_DIR/raze_out_${label}" "$archive" \
				>> "$raze_times_file"
		else
			run_and_measure_seconds \
				"$TMP_DIR/raze_out_${label}" \
				"$ROOT_DIR/raze" x -idq -o+ \
				-op"$TMP_DIR/raze_out_${label}" "$archive" \
				>> "$raze_times_file"
		fi
	done

	log "running $RUNS runs [$label] unrar"
	for _ in $(seq 1 "$RUNS"); do
		if [[ "$needs_password" -eq 1 ]]; then
			run_and_measure_seconds \
				"$TMP_DIR/unrar_out_${label}" \
				"$UNRAR_BIN" x -idq -o+ -mt"$UNRAR_THREADS" -p"$PASSWORD" \
				"$archive" "$TMP_DIR/unrar_out_${label}/" \
				>> "$unrar_times_file"
		else
			run_and_measure_seconds \
				"$TMP_DIR/unrar_out_${label}" \
				"$UNRAR_BIN" x -idq -o+ -mt"$UNRAR_THREADS" \
				"$archive" "$TMP_DIR/unrar_out_${label}/" \
				>> "$unrar_times_file"
		fi
	done

	sort -n "$raze_times_file" > "$raze_sorted_file"
	sort -n "$unrar_times_file" > "$unrar_sorted_file"
	raze_p50="$(median_from_stdin < "$raze_sorted_file")"
	unrar_p50="$(median_from_stdin < "$unrar_sorted_file")"
	raze_p90="$(percentile_from_file "$raze_sorted_file" 9 10)"
	unrar_p90="$(percentile_from_file "$unrar_sorted_file" 9 10)"
	raze_mbps="$(awk -v b="$bytes" -v t="$raze_p50" \
		'BEGIN { printf "%.2f", (b / 1048576.0) / t }')"
	unrar_mbps="$(awk -v b="$bytes" -v t="$unrar_p50" \
		'BEGIN { printf "%.2f", (b / 1048576.0) / t }')"
	gap_pct="$(awk -v r="$raze_p50" -v u="$unrar_p50" \
		'BEGIN { printf "%.2f", ((r - u) / u) * 100.0 }')"

	log "$label: raze p50=${raze_p50}s p90=${raze_p90}s (${raze_mbps} MiB/s), \
unrar p50=${unrar_p50}s p90=${unrar_p90}s (${unrar_mbps} MiB/s), gap=${gap_pct}%"
	if awk -v g="$gap_pct" -v t="$TARGET_GAP_PCT" 'BEGIN { exit !(g > t) }'; then
		warn "$label is outside target (>${TARGET_GAP_PCT}% slower than unrar)"
	fi
done
