#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STABLE_REPEATS="${STABLE_REPEATS:-3}"
STABLE_RUNS="${STABLE_RUNS:-11}"
STABLE_GAP_PCT="${STABLE_GAP_PCT:-0}"
BENCH_CPU_CORE="${BENCH_CPU_CORE:-2}"
FORCE_REPACK="${FORCE_REPACK:-0}"
UNRAR_THREADS="${UNRAR_THREADS:-1}"
REPORT_DIR="${HOT_REPORT_DIR:-$ROOT_DIR/docs/perf/hot}"
TIMESTAMP="$(date -u +"%Y-%m-%d_%H%M%S")"
REPORT_PATH="${REPORT_DIR}/${TIMESTAMP}_hot_solid_stable.md"

log() {
	printf '[bench-hot-solid-stable] %s\n' "$*"
}

fail() {
	printf '[bench-hot-solid-stable] error: %s\n' "$*" >&2
	exit 1
}

extract_field() {
	local report_path="$1"
	local field_index="$2"

	awk -F'|' '
		$2 ~ /^[[:space:]]*enwik8[[:space:]]*$/ &&
		$3 ~ /^[[:space:]]*solid[[:space:]]*$/ {
			gsub(/^[[:space:]]+|[[:space:]]+$/, "", $'"$field_index"');
			print $'"$field_index"';
			exit
		}
	' "$report_path"
}

[[ "$STABLE_REPEATS" -gt 0 ]] || fail "STABLE_REPEATS must be > 0"
[[ "$STABLE_RUNS" -gt 0 ]] || fail "STABLE_RUNS must be > 0"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$REPORT_DIR"
summary_tsv="$TMP_DIR/summary.tsv"

log "running ${STABLE_REPEATS} repeated hot-solid gates"
for attempt in $(seq 1 "$STABLE_REPEATS"); do
	local_report_dir="$TMP_DIR/attempt_${attempt}"
	log "attempt ${attempt}/${STABLE_REPEATS}"
	set +e
	HOT_REPORT_DIR="$local_report_dir" \
	RUNS="$STABLE_RUNS" \
	BENCH_CPU_CORE="$BENCH_CPU_CORE" \
	TARGET_GAP_PCT="$STABLE_GAP_PCT" \
	ENFORCE_GATE=1 \
	UNRAR_THREADS="$UNRAR_THREADS" \
	FORCE_REPACK="$FORCE_REPACK" \
	"$ROOT_DIR/bench/bench_hot_solid.sh"
	attempt_rc=$?
	set -e

	attempt_report="$(ls -1 "$local_report_dir"/*_hot_solid.md 2>/dev/null | tail -n 1)"
	[[ -n "$attempt_report" ]] || fail "attempt ${attempt}: missing hot-solid report"

	raze_p50="$(extract_field "$attempt_report" 5)"
	unrar_p50="$(extract_field "$attempt_report" 7)"
	gap_pct="$(extract_field "$attempt_report" 11)"
	gate="$(extract_field "$attempt_report" 12)"
	if [[ -z "$raze_p50" || -z "$unrar_p50" || -z "$gap_pct" || -z "$gate" ]]; then
		fail "attempt ${attempt}: failed to parse report $attempt_report"
	fi

	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
		"$attempt" "$raze_p50" "$unrar_p50" "$gap_pct" "$gate" \
		"$attempt_rc" "$attempt_report" >> "$summary_tsv"
done

all_pass=1
while IFS=$'\t' read -r _ _ _ _ gate attempt_rc _; do
	if [[ "$gate" != "pass" || "$attempt_rc" -ne 0 ]]; then
		all_pass=0
	fi
done < "$summary_tsv"

{
	echo "# Hot Solid Stable Benchmark Report"
	echo
	echo "- Timestamp (UTC): $(date -u +"%Y-%m-%d %H:%M:%S")"
	echo "- Host: $(hostname)"
	echo "- raze rev: $(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
	echo "- Comparator: unrar -mt${UNRAR_THREADS}"
	echo "- STABLE_REPEATS: ${STABLE_REPEATS}"
	echo "- STABLE_RUNS: ${STABLE_RUNS}"
	echo "- STABLE_GAP_PCT: ${STABLE_GAP_PCT}"
	echo "- BENCH_CPU_CORE: ${BENCH_CPU_CORE}"
	echo "- FORCE_REPACK: ${FORCE_REPACK}"
	echo
	echo "| Attempt | raze p50 (s) | unrar p50 (s) | Gap % | Gate | Exit | Source report |"
	echo "|---:|---:|---:|---:|---|---:|---|"
	while IFS=$'\t' read -r attempt raze_p50 unrar_p50 gap_pct gate attempt_rc src_report; do
		echo "| ${attempt} | ${raze_p50} | ${unrar_p50} | ${gap_pct} | ${gate} | ${attempt_rc} | \`$(basename "$src_report")\` |"
	done < "$summary_tsv"
	echo
	echo "Stable pass criterion: all attempts must pass with gap <= ${STABLE_GAP_PCT}%."
	if [[ "$all_pass" -eq 1 ]]; then
		echo
		echo "Result: PASS"
	else
		echo
		echo "Result: FAIL"
	fi
} > "$REPORT_PATH"

log "report written: $REPORT_PATH"
if [[ "$all_pass" -ne 1 ]]; then
	fail "stable gate failed: one or more attempts exceeded ${STABLE_GAP_PCT}%"
fi

log "stable gate passed"
