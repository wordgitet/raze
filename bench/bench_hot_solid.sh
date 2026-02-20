#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNS="${RUNS:-11}"
FORCE_REPACK="${FORCE_REPACK:-0}"
TARGET_GAP_PCT="${TARGET_GAP_PCT:-10}"
ENFORCE_GATE="${ENFORCE_GATE:-0}"
UNRAR_THREADS="${UNRAR_THREADS:-1}"
RAR_BIN="${RAR_BIN:-$("$ROOT_DIR"/scripts/find_rar.sh || true)}"
UNRAR_BIN="${UNRAR_BIN:-$("$ROOT_DIR"/scripts/find_unrar.sh || true)}"
SOURCE_DIR="${ROOT_DIR}/corpus/upstream/enwik8"
ARCHIVE_DIR="${CORPUS_EXTERNAL_ARCHIVE_DIR:-$ROOT_DIR/corpus/local/external/archives}"
ARCHIVE_PATH="${ARCHIVE_DIR}/enwik8_solid.rar"
REPORT_DIR="${HOT_REPORT_DIR:-$ROOT_DIR/docs/perf/hot}"
TIMESTAMP="$(date -u +"%Y-%m-%d_%H%M%S")"
REPORT_PATH="${REPORT_DIR}/${TIMESTAMP}_hot_solid.md"

log() {
	printf '[bench-hot-solid] %s\n' "$*"
}

fail() {
	printf '[bench-hot-solid] error: %s\n' "$*" >&2
	exit 1
}

warn() {
	printf '[bench-hot-solid] warning: %s\n' "$*" >&2
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

build_archive_if_needed() {
	if [[ "$FORCE_REPACK" -eq 0 && -f "$ARCHIVE_PATH" ]]; then
		log "archive already present: $ARCHIVE_PATH"
		return
	fi
	[[ -n "$RAR_BIN" ]] || fail "rar binary not found for repack."
	mkdir -p "$ARCHIVE_DIR"
	log "building enwik8 solid archive"
	rm -f "$ARCHIVE_PATH"
	(
		cd "$SOURCE_DIR"
		"$RAR_BIN" a -idq -ma5 -m5 -s "$ARCHIVE_PATH" .
	)
}

write_report() {
	local bytes="$1"
	local raze_p50="$2"
	local raze_p90="$3"
	local unrar_p50="$4"
	local unrar_p90="$5"
	local raze_mibs="$6"
	local unrar_mibs="$7"
	local gap_pct="$8"
	local gate="$9"
	local host_name kernel cpu_model raze_rev rar_version unrar_version

	host_name="$(hostname)"
	kernel="$(uname -srvmo 2>/dev/null || uname -a)"
	cpu_model="$(lscpu 2>/dev/null | awk -F: '/Model name/ {gsub(/^[ \t]+/, "", $2); print $2; exit}')"
	if [[ -z "$cpu_model" && -f /proc/cpuinfo ]]; then
		cpu_model="$(awk -F: '/model name/ {gsub(/^[ \t]+/, "", $2); print $2; exit}' /proc/cpuinfo)"
	fi
	if [[ -z "$cpu_model" ]]; then
		cpu_model="unknown"
	fi
	raze_rev="$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
	rar_version="n/a"
	if [[ -n "$RAR_BIN" ]]; then
		rar_version="$("$RAR_BIN" 2>&1 | awk 'NF && first == "" { first = $0 } END { if (first != "") print first }' | sed 's/[[:space:]]\+/ /g')"
	fi
	unrar_version="$("$UNRAR_BIN" 2>&1 | awk 'NF && first == "" { first = $0 } END { if (first != "") print first }' | sed 's/[[:space:]]\+/ /g')"
	if [[ -z "$rar_version" ]]; then
		rar_version="unknown"
	fi
	if [[ -z "$unrar_version" ]]; then
		unrar_version="unknown"
	fi

	mkdir -p "$REPORT_DIR"
	{
		echo "# Hot Solid Benchmark Report (enwik8/solid)"
		echo
		echo "- Timestamp (UTC): $(date -u +"%Y-%m-%d %H:%M:%S")"
		echo "- Host: $host_name"
		echo "- Kernel: $kernel"
		echo "- CPU: $cpu_model"
		echo "- raze rev: $raze_rev"
		echo "- RUNS: $RUNS"
		echo "- Comparator: unrar -mt$UNRAR_THREADS"
		echo "- BENCH_CPU_CORE: ${BENCH_CPU_CORE:-none}"
		echo "- TARGET_GAP_PCT: $TARGET_GAP_PCT"
		echo "- ENFORCE_GATE: $ENFORCE_GATE"
		echo "- FORCE_REPACK: $FORCE_REPACK"
		echo "- Archive: $ARCHIVE_PATH"
		echo "- rar: $rar_version"
		echo "- unrar: $unrar_version"
		echo
		echo "| Corpus | Mode | Size (MiB) | raze p50 (s) | raze p90 (s) | unrar p50 (s) | unrar p90 (s) | raze MiB/s | unrar MiB/s | Gap % | Gate |"
		echo "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|"
		echo "| enwik8 | solid | $(awk -v b="$bytes" 'BEGIN { printf "%.2f", b / 1048576.0 }') | $raze_p50 | $raze_p90 | $unrar_p50 | $unrar_p90 | $raze_mibs | $unrar_mibs | $gap_pct | $gate |"
		echo
		echo "Gate semantics: fail when gap > ${TARGET_GAP_PCT}% and ENFORCE_GATE=1."
	} > "$REPORT_PATH"
}

[[ -n "$UNRAR_BIN" ]] || fail "unrar binary not found."
[[ -x "$ROOT_DIR/raze" ]] || fail "raze binary not found; run make first."

log "ensuring enwik8 corpus is present"
"$ROOT_DIR/scripts/corpus_fetch.sh" >/dev/null
[[ -d "$SOURCE_DIR" ]] || fail "source corpus missing: $SOURCE_DIR"
build_archive_if_needed
[[ -f "$ARCHIVE_PATH" ]] || fail "archive missing: $ARCHIVE_PATH"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

bytes="$(du -sb "$SOURCE_DIR" | awk '{print $1}')"
[[ "$bytes" -gt 0 ]] || fail "source corpus is empty: $SOURCE_DIR"

log "warmup [raze]"
run_and_measure_seconds \
	"$TMP_DIR/raze_warmup" \
	"$ROOT_DIR/raze" x -idq -o+ -op"$TMP_DIR/raze_warmup" "$ARCHIVE_PATH" \
	>/dev/null

log "warmup [unrar]"
run_and_measure_seconds \
	"$TMP_DIR/unrar_warmup" \
	"$UNRAR_BIN" x -idq -o+ -mt"$UNRAR_THREADS" "$ARCHIVE_PATH" "$TMP_DIR/unrar_warmup/" \
	>/dev/null

raze_times_file="$TMP_DIR/raze_times.txt"
unrar_times_file="$TMP_DIR/unrar_times.txt"
raze_sorted_file="$TMP_DIR/raze_sorted.txt"
unrar_sorted_file="$TMP_DIR/unrar_sorted.txt"

log "running $RUNS runs [raze]"
for _ in $(seq 1 "$RUNS"); do
	run_and_measure_seconds \
		"$TMP_DIR/raze_out" \
		"$ROOT_DIR/raze" x -idq -o+ -op"$TMP_DIR/raze_out" "$ARCHIVE_PATH" \
		>> "$raze_times_file"
done

log "running $RUNS runs [unrar]"
for _ in $(seq 1 "$RUNS"); do
	run_and_measure_seconds \
		"$TMP_DIR/unrar_out" \
		"$UNRAR_BIN" x -idq -o+ -mt"$UNRAR_THREADS" "$ARCHIVE_PATH" "$TMP_DIR/unrar_out/" \
		>> "$unrar_times_file"
done

sort -n "$raze_times_file" > "$raze_sorted_file"
sort -n "$unrar_times_file" > "$unrar_sorted_file"

raze_p50="$(median_from_stdin < "$raze_sorted_file")"
unrar_p50="$(median_from_stdin < "$unrar_sorted_file")"
raze_p90="$(percentile_from_file "$raze_sorted_file" 9 10)"
unrar_p90="$(percentile_from_file "$unrar_sorted_file" 9 10)"
raze_mibs="$(awk -v b="$bytes" -v t="$raze_p50" 'BEGIN { printf "%.2f", (b / 1048576.0) / t }')"
unrar_mibs="$(awk -v b="$bytes" -v t="$unrar_p50" 'BEGIN { printf "%.2f", (b / 1048576.0) / t }')"
gap_pct="$(awk -v r="$raze_p50" -v u="$unrar_p50" 'BEGIN { printf "%.2f", ((r - u) / u) * 100.0 }')"

gate="pass"
if awk -v g="$gap_pct" -v t="$TARGET_GAP_PCT" 'BEGIN { exit !(g > t) }'; then
	gate="fail"
fi

log "enwik8/solid: raze p50=${raze_p50}s p90=${raze_p90}s (${raze_mibs} MiB/s), unrar p50=${unrar_p50}s p90=${unrar_p90}s (${unrar_mibs} MiB/s), gap=${gap_pct}%, gate=${gate}"

write_report "$bytes" "$raze_p50" "$raze_p90" "$unrar_p50" \
	"$unrar_p90" "$raze_mibs" "$unrar_mibs" "$gap_pct" "$gate"
log "report written: $REPORT_PATH"

if [[ "$gate" == "fail" && "$ENFORCE_GATE" -ne 0 ]]; then
	fail "hot-solid gate failed: gap ${gap_pct}% exceeds ${TARGET_GAP_PCT}%"
fi
if [[ "$gate" == "fail" ]]; then
	warn "gap exceeds target; rerun with ENFORCE_GATE=1 to hard-fail."
fi
