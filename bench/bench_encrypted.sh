#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNS="${RUNS:-7}"
UNRAR_BIN="${UNRAR_BIN:-$(command -v unrar || true)}"
UNRAR_THREADS="${UNRAR_THREADS:-1}"
RAR_BIN="${RAR_BIN:-$("$ROOT_DIR"/scripts/find_rar.sh || true)}"
PASSWORD="${PASSWORD:-secret}"

log() {
	printf '[bench-encrypted] %s\n' "$*"
}

fail() {
	printf '[bench-encrypted] error: %s\n' "$*" >&2
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
	awk -v s="$start_ns" -v e="$end_ns" \
		'BEGIN { printf "%.6f\n", (e - s) / 1000000000.0 }'
}

run_one_bench() {
	local archive="$1"
	local label="$2"
	local bytes="$3"
	local tmp_dir="$4"
	local raze_times_file
	local unrar_times_file
	local raze_sorted_file
	local unrar_sorted_file
	local raze_p50
	local unrar_p50
	local raze_p90
	local unrar_p90
	local raze_mbps
	local unrar_mbps
	local gap_pct
	local gate_fail=0

	raze_times_file="$tmp_dir/raze_${label}.txt"
	unrar_times_file="$tmp_dir/unrar_${label}.txt"
	raze_sorted_file="$tmp_dir/raze_sorted_${label}.txt"
	unrar_sorted_file="$tmp_dir/unrar_sorted_${label}.txt"

	log "warmup [$label] raze"
	run_and_measure_seconds \
		"$tmp_dir/raze_warmup" \
		"$ROOT_DIR/raze" x -idq -o+ -p"$PASSWORD" \
		-op"$tmp_dir/raze_warmup" "$archive" \
		>/dev/null

	log "warmup [$label] unrar"
	run_and_measure_seconds \
		"$tmp_dir/unrar_warmup" \
		"$UNRAR_BIN" x -idq -o+ -mt"$UNRAR_THREADS" -p"$PASSWORD" \
		"$archive" "$tmp_dir/unrar_warmup/" \
		>/dev/null

	log "running $RUNS runs [$label] raze"
	for _ in $(seq 1 "$RUNS"); do
		run_and_measure_seconds \
			"$tmp_dir/raze_out" \
			"$ROOT_DIR/raze" x -idq -o+ -p"$PASSWORD" \
			-op"$tmp_dir/raze_out" "$archive" \
			>> "$raze_times_file"
	done

	log "running $RUNS runs [$label] unrar"
	for _ in $(seq 1 "$RUNS"); do
		run_and_measure_seconds \
			"$tmp_dir/unrar_out" \
			"$UNRAR_BIN" x -idq -o+ -mt"$UNRAR_THREADS" -p"$PASSWORD" \
			"$archive" "$tmp_dir/unrar_out/" \
			>> "$unrar_times_file"
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

	if awk -v g="$gap_pct" 'BEGIN { exit !(g > 10.0) }'; then
		log "$label gate failed: raze is more than 10% slower than unrar"
		gate_fail=1
	fi

	return "$gate_fail"
}

[[ -n "$UNRAR_BIN" ]] || fail "unrar binary not found. Set UNRAR_BIN."
[[ -n "$RAR_BIN" ]] || fail "rar binary not found. Set RAR_BIN."

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

SRC_DIR="$TMP_DIR/src"
DATA_ARCHIVE="$TMP_DIR/data_encrypted.rar"
HEAD_ARCHIVE="$TMP_DIR/header_encrypted.rar"
mkdir -p "$SRC_DIR/enc"

for i in $(seq 1 12000); do
	printf 'encrypted-bench-line-%05d repeatable payload\n' "$i" \
		>> "$SRC_DIR/enc/text.txt"
done
dd if=/dev/urandom of="$SRC_DIR/enc/blob.bin" bs=1K count=2048 status=none

(
	cd "$SRC_DIR"
	"$RAR_BIN" a -idq -ma5 -m3 -s- -r -p"$PASSWORD" "$DATA_ARCHIVE" ./enc
	"$RAR_BIN" a -idq -ma5 -m3 -s- -r -hp"$PASSWORD" "$HEAD_ARCHIVE" ./enc
)

bytes="$(du -sb "$SRC_DIR" | awk '{print $1}')"
[[ "$bytes" -gt 0 ]] || fail "source fixture size is zero"

gate_failed=0
run_one_bench "$DATA_ARCHIVE" "data-encrypted" "$bytes" "$TMP_DIR" || gate_failed=1
run_one_bench "$HEAD_ARCHIVE" "header-encrypted" "$bytes" "$TMP_DIR" || gate_failed=1

if [[ "$gate_failed" -ne 0 ]]; then
	fail "performance gate failed: one or more encrypted benches exceeded 10% gap"
fi

log "performance gates passed (<=10% slower than unrar)"
