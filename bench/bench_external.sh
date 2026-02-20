#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNS="${RUNS:-7}"
FORCE_REPACK="${FORCE_REPACK:-0}"
TARGET_GAP_PCT="${TARGET_GAP_PCT:-10}"
PASSWORD="${PASSWORD:-secret}"
UNRAR_THREADS="${UNRAR_THREADS:-1}"
RAR_BIN="${RAR_BIN:-$("$ROOT_DIR"/scripts/find_rar.sh || true)}"
UNRAR_BIN="${UNRAR_BIN:-$("$ROOT_DIR"/scripts/find_unrar.sh || true)}"
ARCHIVE_DIR="${CORPUS_EXTERNAL_ARCHIVE_DIR:-$ROOT_DIR/corpus/local/external/archives}"
REPORT_DIR="${EXTERNAL_REPORT_DIR:-$ROOT_DIR/docs/perf/external}"
TIMESTAMP="$(date -u +"%Y-%m-%d_%H%M%S")"
REPORT_PATH="$REPORT_DIR/${TIMESTAMP}_external_bench.md"
CORPORA=(calgary canterbury enwik8)
MODES=(store fast solid encrypted-data encrypted-headers)

log() {
	printf '[bench-external] %s\n' "$*"
}

fail() {
	printf '[bench-external] error: %s\n' "$*" >&2
	exit 1
}

warn() {
	printf '[bench-external] warning: %s\n' "$*" >&2
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

archive_path_for() {
	local corpus="$1"
	local mode="$2"

	printf '%s/%s_%s.rar\n' "$ARCHIVE_DIR" "$corpus" "$mode"
}

build_archive_for_mode() {
	local src_dir="$1"
	local archive="$2"
	local mode="$3"
	local -a rar_opts

	case "$mode" in
	store)
		rar_opts=(-m0 -s-)
		;;
	fast)
		rar_opts=(-m1 -s-)
		;;
	solid)
		rar_opts=(-m5 -s)
		;;
	encrypted-data)
		rar_opts=(-m3 -s- "-p$PASSWORD")
		;;
	encrypted-headers)
		rar_opts=(-m3 -s- "-hp$PASSWORD")
		;;
	*)
		fail "unsupported mode '$mode'"
		;;
	esac

	rm -f "$archive"
	(
		cd "$src_dir"
		"$RAR_BIN" a -idq -ma5 -r "${rar_opts[@]}" "$archive" .
	)
}

run_entry_bench() {
	local corpus="$1"
	local mode="$2"
	local source_dir="$3"
	local archive="$4"
	local results_tsv="$5"
	local label="${corpus}/${mode}"
	local need_password=0
	local bytes
	local raze_times_file
	local unrar_times_file
	local raze_sorted_file
	local unrar_sorted_file
	local raze_p50
	local raze_p90
	local unrar_p50
	local unrar_p90
	local raze_mibs
	local unrar_mibs
	local gap_pct
	local gate

	if [[ "$mode" == "encrypted-data" || "$mode" == "encrypted-headers" ]]; then
		need_password=1
	fi

	bytes="$(du -sb "$source_dir" | awk '{print $1}')"
	[[ "$bytes" -gt 0 ]] || fail "source corpus size is zero: $source_dir"

	raze_times_file="$TMP_DIR/raze_${corpus}_${mode}.txt"
	unrar_times_file="$TMP_DIR/unrar_${corpus}_${mode}.txt"
	raze_sorted_file="$TMP_DIR/raze_sorted_${corpus}_${mode}.txt"
	unrar_sorted_file="$TMP_DIR/unrar_sorted_${corpus}_${mode}.txt"

	log "$label: warmup [raze]"
	if [[ "$need_password" -eq 1 ]]; then
		run_and_measure_seconds \
			"$TMP_DIR/raze_warmup_${corpus}_${mode}" \
			"$ROOT_DIR/raze" x -idq -o+ -p"$PASSWORD" \
			-op"$TMP_DIR/raze_warmup_${corpus}_${mode}" "$archive" \
			>/dev/null
	else
		run_and_measure_seconds \
			"$TMP_DIR/raze_warmup_${corpus}_${mode}" \
			"$ROOT_DIR/raze" x -idq -o+ \
			-op"$TMP_DIR/raze_warmup_${corpus}_${mode}" "$archive" \
			>/dev/null
	fi

	log "$label: warmup [unrar]"
	if [[ "$need_password" -eq 1 ]]; then
		run_and_measure_seconds \
			"$TMP_DIR/unrar_warmup_${corpus}_${mode}" \
			"$UNRAR_BIN" x -idq -o+ -mt"$UNRAR_THREADS" -p"$PASSWORD" \
			"$archive" "$TMP_DIR/unrar_warmup_${corpus}_${mode}/" \
			>/dev/null
	else
		run_and_measure_seconds \
			"$TMP_DIR/unrar_warmup_${corpus}_${mode}" \
			"$UNRAR_BIN" x -idq -o+ -mt"$UNRAR_THREADS" \
			"$archive" "$TMP_DIR/unrar_warmup_${corpus}_${mode}/" \
			>/dev/null
	fi

	log "$label: running $RUNS runs [raze]"
	for _ in $(seq 1 "$RUNS"); do
		if [[ "$need_password" -eq 1 ]]; then
			run_and_measure_seconds \
				"$TMP_DIR/raze_out_${corpus}_${mode}" \
				"$ROOT_DIR/raze" x -idq -o+ -p"$PASSWORD" \
				-op"$TMP_DIR/raze_out_${corpus}_${mode}" "$archive" \
				>> "$raze_times_file"
		else
			run_and_measure_seconds \
				"$TMP_DIR/raze_out_${corpus}_${mode}" \
				"$ROOT_DIR/raze" x -idq -o+ \
				-op"$TMP_DIR/raze_out_${corpus}_${mode}" "$archive" \
				>> "$raze_times_file"
		fi
	done

	log "$label: running $RUNS runs [unrar]"
	for _ in $(seq 1 "$RUNS"); do
		if [[ "$need_password" -eq 1 ]]; then
			run_and_measure_seconds \
				"$TMP_DIR/unrar_out_${corpus}_${mode}" \
				"$UNRAR_BIN" x -idq -o+ -mt"$UNRAR_THREADS" -p"$PASSWORD" \
				"$archive" "$TMP_DIR/unrar_out_${corpus}_${mode}/" \
				>> "$unrar_times_file"
		else
			run_and_measure_seconds \
				"$TMP_DIR/unrar_out_${corpus}_${mode}" \
				"$UNRAR_BIN" x -idq -o+ -mt"$UNRAR_THREADS" \
				"$archive" "$TMP_DIR/unrar_out_${corpus}_${mode}/" \
				>> "$unrar_times_file"
		fi
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
		GATE_FAILURES=$((GATE_FAILURES + 1))
	fi

	log "$label: raze p50=${raze_p50}s p90=${raze_p90}s (${raze_mibs} MiB/s), unrar p50=${unrar_p50}s p90=${unrar_p90}s (${unrar_mibs} MiB/s), gap=${gap_pct}%, gate=${gate}"

	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
		"$corpus" "$mode" "$bytes" "$raze_p50" "$raze_p90" \
		"$unrar_p50" "$unrar_p90" "$raze_mibs" "$unrar_mibs" \
		"$gap_pct" "$gate" >> "$results_tsv"
}

write_report() {
	local results_tsv="$1"
	local host_name
	local kernel
	local cpu_model
	local raze_rev
	local rar_version
	local unrar_version

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
	rar_version="$("$RAR_BIN" 2>&1 | awk 'NF && first == "" { first = $0 } END { if (first != "") print first }' | sed 's/[[:space:]]\+/ /g')"
	unrar_version="$("$UNRAR_BIN" 2>&1 | awk 'NF && first == "" { first = $0 } END { if (first != "") print first }' | sed 's/[[:space:]]\+/ /g')"
	if [[ -z "$rar_version" ]]; then
		rar_version="unknown"
	fi
	if [[ -z "$unrar_version" ]]; then
		unrar_version="unknown"
	fi

	mkdir -p "$REPORT_DIR"
	{
		echo "# External Corpus Benchmark Report"
		echo
		echo "- Timestamp (UTC): $(date -u +"%Y-%m-%d %H:%M:%S")"
		echo "- Host: $host_name"
		echo "- Kernel: $kernel"
		echo "- CPU: $cpu_model"
		echo "- raze rev: $raze_rev"
		echo "- Comparator: unrar -mt$UNRAR_THREADS"
		echo "- BENCH_CPU_CORE: ${BENCH_CPU_CORE:-none}"
		echo "- RUNS: $RUNS"
		echo "- TARGET_GAP_PCT: $TARGET_GAP_PCT"
		echo "- FORCE_REPACK: $FORCE_REPACK"
		echo "- rar: $rar_version"
		echo "- unrar: $unrar_version"
		echo
		echo "| Corpus | Mode | Size (MiB) | raze p50 (s) | raze p90 (s) | unrar p50 (s) | unrar p90 (s) | raze MiB/s | unrar MiB/s | Gap % | Gate |"
		echo "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|"
		while IFS=$'\t' read -r corpus mode bytes raze_p50 raze_p90 unrar_p50 unrar_p90 raze_mibs unrar_mibs gap gate; do
			size_mib="$(awk -v b="$bytes" 'BEGIN { printf "%.2f", b / 1048576.0 }')"
			echo "| $corpus | $mode | $size_mib | $raze_p50 | $raze_p90 | $unrar_p50 | $unrar_p90 | $raze_mibs | $unrar_mibs | $gap | $gate |"
		done < "$results_tsv"
		echo
		echo "Gate semantics: fail when gap > ${TARGET_GAP_PCT}% (raze slower than unrar)."
		echo
		if [[ "$GATE_FAILURES" -eq 0 ]]; then
			echo "Result: PASS"
		else
			echo "Result: FAIL (${GATE_FAILURES} gate failures)"
		fi
	} > "$REPORT_PATH"
}

[[ -n "$RAR_BIN" ]] || fail "rar binary not found."
[[ -n "$UNRAR_BIN" ]] || fail "unrar binary not found."
[[ -x "$ROOT_DIR/raze" ]] || fail "raze binary not found; run make first."

log "ensuring external corpora are present"
"$ROOT_DIR/scripts/corpus_fetch.sh"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
RESULTS_TSV="$TMP_DIR/results.tsv"
GATE_FAILURES=0

mkdir -p "$ARCHIVE_DIR"

for corpus in "${CORPORA[@]}"; do
	source_dir="$ROOT_DIR/corpus/upstream/$corpus"
	[[ -d "$source_dir" ]] || fail "source corpus missing: $source_dir"

	for mode in "${MODES[@]}"; do
		archive="$(archive_path_for "$corpus" "$mode")"
		if [[ "$FORCE_REPACK" -ne 0 || ! -f "$archive" ]]; then
			log "$corpus/$mode: building archive"
			build_archive_for_mode "$source_dir" "$archive" "$mode"
		else
			log "$corpus/$mode: archive already present, skipping repack"
		fi

		run_entry_bench "$corpus" "$mode" "$source_dir" "$archive" "$RESULTS_TSV"
	done
done

write_report "$RESULTS_TSV"
log "report written: $REPORT_PATH"

if [[ "$GATE_FAILURES" -ne 0 ]]; then
	fail "external benchmark gate failed for ${GATE_FAILURES} corpus/mode entries"
fi

log "all external benchmark gates passed"
