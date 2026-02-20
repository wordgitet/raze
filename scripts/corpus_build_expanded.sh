#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXP_ROOT="${CORPUS_EXPANDED_ROOT:-$ROOT_DIR/corpus/local/expanded}"
SOURCE_DIR="${CORPUS_EXPANDED_SOURCE_DIR:-$EXP_ROOT/source}"
ARCHIVE_DIR="${CORPUS_EXPANDED_ARCHIVE_DIR:-$EXP_ROOT/archives}"
CORRUPT_DIR="${CORPUS_EXPANDED_CORRUPT_DIR:-$EXP_ROOT/corrupt}"
STAMP_DIR="${CORPUS_EXPANDED_STAMP_DIR:-$EXP_ROOT/stamps}"
FORCE=0

if [[ "${1:-}" == "--force" ]]; then
	FORCE=1
fi

log() {
	printf '[corpus-expand] %s\n' "$*"
}

die() {
	printf '[corpus-expand] error: %s\n' "$*" >&2
	exit 1
}

have_cmd() {
	command -v "$1" >/dev/null 2>&1
}

is_windows_shell() {
	case "$(uname -s)" in
	MINGW*|MSYS*|CYGWIN*)
		return 0
		;;
	*)
		return 1
		;;
	esac
}

max_relative_file_path_len() {
	local root="$1"
	local max_len

	max_len="$(find "$root" -type f | sed "s#^$root/##" | awk '
		{ n = length($0); if (n > max) max = n }
		END { print max + 0 }
	')"
	printf '%s\n' "$max_len"
}

RAR_BIN="${RAR_BIN:-$("$ROOT_DIR"/scripts/find_rar.sh || true)}"
if [[ -z "$RAR_BIN" ]]; then
	die "rar binary not found. Set RAR_BIN or install rar."
fi

mkdir -p "$SOURCE_DIR" "$ARCHIVE_DIR" "$CORRUPT_DIR" "$STAMP_DIR"

create_small_files_fixture() {
	local root="$1"
	local dirs=60
	local files_per_dir=160
	local d
	local f
	local dir_path

	if [[ -d "$root" ]] && find "$root" -type f -print -quit | grep -q .; then
		return
	fi

	log "creating small-files stress fixture"
	rm -rf "$root"
	mkdir -p "$root"

	for d in $(seq 1 "$dirs"); do
		dir_path="$root/set_$(printf '%03d' "$d")"
		mkdir -p "$dir_path"
		for f in $(seq 1 "$files_per_dir"); do
			printf 'tiny-file d=%03d f=%03d\n' "$d" "$f" > \
				"$dir_path/tiny_$(printf '%03d' "$f").txt"
		done
	done
}

create_text_fixture() {
	local root="$1"
	local i

	if [[ -d "$root" ]] && find "$root" -type f -print -quit | grep -q .; then
		return
	fi

	log "creating text-heavy fixture"
	rm -rf "$root"
	mkdir -p "$root"

	{
		printf 'ts,level,service,message\n'
		for i in $(seq 1 180000); do
			printf '%d,info,svc_%02d,msg_%08d_payload_%08d\n' \
				"$((1700000000 + i))" "$((i % 23))" "$i" \
				"$(((i * 104729) % 100000000))"
		done
	} > "$root/log.csv"

	{
		for i in $(seq 1 120000); do
			printf '{"id":%d,"group":"g_%03d","kind":"k_%03d","v":%d}\n' \
				"$i" "$((i % 500))" "$((i % 350))" \
				"$(((i * 99991) % 1000000))"
		done
	} > "$root/events.ndjson"

	{
		printf '# synthetic source-like text\n'
		for i in $(seq 1 90000); do
			printf 'fn_%06d(arg_%d) -> value_%08d\n' \
				"$i" "$((i % 19))" "$(((i * 7919) % 100000000))"
		done
	} > "$root/source_like.txt"
}

create_binary_fixture() {
	local root="$1"

	if [[ -d "$root" ]] && find "$root" -type f -print -quit | grep -q .; then
		return
	fi

	log "creating binary-heavy fixture"
	rm -rf "$root"
	mkdir -p "$root"

	dd if=/dev/zero of="$root/zeros_16mb.bin" bs=1M count=16 status=none
	dd if=/dev/urandom of="$root/random_16mb.bin" bs=1M count=16 status=none
	dd if=/dev/urandom of="$root/random_32mb.bin" bs=1M count=32 status=none
}

create_db_fixture() {
	local root="$1"
	local i

	if [[ -d "$root" ]] && find "$root" -type f -print -quit | grep -q .; then
		return
	fi

	log "creating database-like fixture"
	rm -rf "$root"
	mkdir -p "$root"

	{
		printf 'id,user,amount,region\n'
		for i in $(seq 1 220000); do
			printf '%d,user_%06d,%d,region_%02d\n' \
				"$i" "$((1 + (i % 10000)))" \
				"$(((i * 65537) % 10000000))" "$((i % 31))"
		done
	} > "$root/sales.csv"

	if have_cmd sqlite3; then
		sqlite3 "$root/synthetic.sqlite" <<'SQL'
PRAGMA journal_mode=OFF;
PRAGMA synchronous=OFF;
DROP TABLE IF EXISTS rowlog;
CREATE TABLE rowlog (
	id INTEGER PRIMARY KEY,
	account TEXT NOT NULL,
	event TEXT NOT NULL,
	value INTEGER NOT NULL,
	ts INTEGER NOT NULL
);
WITH RECURSIVE seq(i) AS (
	VALUES(1)
	UNION ALL
	SELECT i + 1 FROM seq WHERE i < 220000
)
INSERT INTO rowlog(account, event, value, ts)
SELECT
	printf('acct_%05d', i % 5000),
	printf('evt_%03d', i % 200),
	(i * 3571) % 1000000,
	1700000000 + i
FROM seq;
CREATE INDEX rowlog_account_idx ON rowlog(account);
CREATE INDEX rowlog_ts_idx ON rowlog(ts);
SQL
	fi
}

create_path_stress_fixture() {
	local root="$1"
	local depth=48
	local segment='deepseg_0123456789abcd'
	local dir="$root"
	local i
	local file_path
	local max_rel_path

	if is_windows_shell; then
		# Keep Windows path stress practical for Win32 API limits.
		depth=6
	fi

	if [[ -d "$root" ]] && find "$root" -type f -print -quit | grep -q .; then
		if is_windows_shell; then
			max_rel_path="$(max_relative_file_path_len "$root")"
			if [[ "$max_rel_path" -le 180 ]]; then
				return 0
			fi
			log "rebuilding path-stress fixture for windows-safe depth"
		else
			return 0
		fi
	fi

	log "creating path-stress fixture"
	rm -rf "$root"
	mkdir -p "$root"

	for i in $(seq 1 "$depth"); do
		dir="$dir/$segment"
		mkdir -p "$dir"
	done

	file_path="$dir/final_long_path_payload.txt"
	printf 'path stress marker\n' > "$file_path"

	# Additional collision-like names and different extensions.
	printf 'same base, different extension\n' > "$root/name_collision.data"
	printf 'same base, different extension\n' > "$root/name_collision.txt"
}

create_source_fixture() {
	local root="$1"
	local i

	if [[ -d "$root" ]] && find "$root" -type f -print -quit | grep -q .; then
		return
	fi

	log "creating source-code fixture"
	rm -rf "$root"
	mkdir -p "$root/c" "$root/h" "$root/rust" "$root/go"

	for i in $(seq 1 220); do
		cat > "$root/h/mod_$(printf '%03d' "$i").h" <<EOF
#ifndef MOD_$(printf '%03d' "$i")_H
#define MOD_$(printf '%03d' "$i")_H

int mod_$(printf '%03d' "$i")_step(int in, int rounds);

#endif
EOF

		cat > "$root/c/mod_$(printf '%03d' "$i").c" <<EOF
#include "mod_$(printf '%03d' "$i").h"

int mod_$(printf '%03d' "$i")_step(int in, int rounds)
{
	int v = in ^ $i;
	int j;

	for (j = 0; j < rounds; ++j)
		v = (v * 1103515245 + 12345 + $i) & 0x7fffffff;

	return v;
}
EOF

		cat > "$root/rust/mod_$(printf '%03d' "$i").rs" <<EOF
pub fn mod_$(printf '%03d' "$i")(mut v: u64, rounds: u32) -> u64 {
	let mut i = 0;
	while i < rounds {
		v = v.wrapping_mul(6364136223846793005).wrapping_add($i);
		i += 1;
	}
	v
}
EOF

		cat > "$root/go/mod_$(printf '%03d' "$i").go" <<EOF
package mods

func Mod$(printf '%03d' "$i")(v uint64, rounds uint32) uint64 {
	var i uint32
	for i = 0; i < rounds; i++ {
		v = (v * 2862933555777941757) + uint64($i)
	}
	return v
}
EOF
	done
}

build_source_fixtures() {
	create_small_files_fixture "$SOURCE_DIR/small_files"
	create_text_fixture "$SOURCE_DIR/text"
	create_binary_fixture "$SOURCE_DIR/binary"
	create_db_fixture "$SOURCE_DIR/databases"
	create_path_stress_fixture "$SOURCE_DIR/path_stress"
	create_source_fixture "$SOURCE_DIR/source_code"
}

compute_source_fingerprint() {
	(
		cd "$SOURCE_DIR"
		find . -type f -print0 | sort -z | xargs -0 sha256sum
	) | sha256sum | awk '{print $1}'
}

rar_version() {
	"$RAR_BIN" | sed -n '1p'
}

split_prefix_for() {
	local archive_name="$1"

	if [[ "$archive_name" == *.part1.rar ]]; then
		printf '%s\n' "${archive_name%.part1.rar}"
		return
	fi
	printf '%s\n' "$archive_name"
}

build_archive() {
	local archive_name="$1"
	shift

	local archive_path="$ARCHIVE_DIR/$archive_name"
	local stamp_path="$STAMP_DIR/$archive_name.stamp"
	local stamp_key="${SOURCE_FINGERPRINT}|$(rar_version)|$*"
	local prefix

	if [[ "$FORCE" -eq 0 && -f "$archive_path" && -f "$stamp_path" ]]; then
		if [[ "$(cat "$stamp_path")" == "$stamp_key" ]]; then
			log "$archive_name: already up to date, skipping"
			return
		fi
	fi

	log "$archive_name: building archive"
	rm -f "$archive_path"
	prefix="$(split_prefix_for "$archive_name")"
	rm -f "$ARCHIVE_DIR/${prefix}.part"*.rar
	(
		cd "$SOURCE_DIR"
		"$RAR_BIN" a -idq -ma5 -r "$@" "$archive_path" .
	)
	printf '%s\n' "$stamp_key" > "$stamp_path"
}

write_truncated_copy() {
	local src="$1"
	local dst="$2"
	local size
	local keep

	size="$(stat -c%s "$src")"
	if [[ "$size" -lt 8192 ]]; then
		keep="$size"
	else
		keep="$((size / 2))"
	fi
	dd if="$src" of="$dst" bs=1 count="$keep" status=none
}

write_bitflip_copy() {
	local src="$1"
	local dst="$2"
	local preferred_offset="${3:-}"
	local size
	local offset

	cp "$src" "$dst"
	size="$(stat -c%s "$src")"
	if [[ -n "$preferred_offset" && "$preferred_offset" -lt "$size" ]]; then
		offset="$preferred_offset"
	elif [[ "$size" -le 32768 ]]; then
		offset="$((size / 2))"
	else
		offset=32768
	fi
	printf '\xff' | dd of="$dst" bs=1 seek="$offset" conv=notrunc status=none
}

build_corrupt_set() {
	local stamp_path="$STAMP_DIR/corrupt_set.stamp"
	local stamp_key="${SOURCE_FINGERPRINT}|$(rar_version)|corrupt-v3"
	local split_copy_root="$CORRUPT_DIR/expanded_fast_split_missing"

	if [[ "$FORCE" -eq 0 && -f "$stamp_path" ]]; then
		if [[ "$(cat "$stamp_path")" == "$stamp_key" ]]; then
			log "corrupt set: already up to date, skipping"
			return
		fi
	fi

	log "building corrupted archive variants"
	rm -rf "$CORRUPT_DIR"
	mkdir -p "$CORRUPT_DIR"

	write_truncated_copy \
		"$ARCHIVE_DIR/expanded_fast.rar" \
		"$CORRUPT_DIR/expanded_fast_truncated.rar"

	write_bitflip_copy \
		"$ARCHIVE_DIR/expanded_best_htb.rar" \
		"$CORRUPT_DIR/expanded_best_htb_bitflip.rar" \
		131072

	write_bitflip_copy \
		"$ARCHIVE_DIR/expanded_best_encrypted_htb.rar" \
		"$CORRUPT_DIR/expanded_best_encrypted_htb_bitflip.rar" \
		2228224

	cp "$ARCHIVE_DIR"/expanded_fast_split.part*.rar "$CORRUPT_DIR"/
	rm -f "$CORRUPT_DIR/expanded_fast_split.part2.rar"

	cp "$ARCHIVE_DIR"/expanded_best_solid_split.part*.rar "$CORRUPT_DIR"/
	rm -f "$CORRUPT_DIR/expanded_best_solid_split.part2.rar"

	mkdir -p "$split_copy_root"
	cp "$ARCHIVE_DIR"/expanded_fast_split.part*.rar "$split_copy_root"/
	rm -f "$split_copy_root/expanded_fast_split.part2.rar"

	printf '%s\n' "$stamp_key" > "$stamp_path"
}

build_source_fixtures
SOURCE_FINGERPRINT="$(compute_source_fingerprint)"

build_archive "expanded_store.rar" -m0 -s-
build_archive "expanded_fast.rar" -m1 -s-
build_archive "expanded_best_solid.rar" -m5 -s
build_archive "expanded_fast_htb.rar" -m1 -s- -htb
build_archive "expanded_best_htb.rar" -m5 -s -htb
build_archive "expanded_best_encrypted.rar" -m5 -s -psecret
build_archive "expanded_best_headers_encrypted.rar" -m5 -s -hpsecret
build_archive "expanded_best_encrypted_htb.rar" -m5 -s -psecret -htb
build_archive "expanded_fast_split.part1.rar" -m1 -s- -v2m
build_archive "expanded_best_solid_split.part1.rar" -m5 -s -v2m

build_corrupt_set

log "done: expanded corpus archives are in $ARCHIVE_DIR"
log "done: corrupted variants are in $CORRUPT_DIR"
