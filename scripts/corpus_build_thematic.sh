#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
THEME_ROOT="${CORPUS_THEMATIC_ROOT:-$ROOT_DIR/corpus/local/thematic}"
SOURCE_DIR="${CORPUS_THEMATIC_SOURCE_DIR:-$THEME_ROOT/source}"
ARCHIVE_DIR="${CORPUS_THEMATIC_ARCHIVE_DIR:-$THEME_ROOT/archives}"
STAMP_DIR="${CORPUS_THEMATIC_STAMP_DIR:-$THEME_ROOT/stamps}"
FORCE=0

if [[ "${1:-}" == "--force" ]]; then
    FORCE=1
fi

log() {
    printf '[corpus-theme] %s\n' "$*"
}

die() {
    printf '[corpus-theme] error: %s\n' "$*" >&2
    exit 1
}

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

RAR_BIN="${RAR_BIN:-$("$ROOT_DIR"/scripts/find_rar.sh || true)}"
if [[ -z "$RAR_BIN" ]]; then
    die "rar binary not found. Set RAR_BIN or install rar."
fi

mkdir -p "$SOURCE_DIR" "$ARCHIVE_DIR" "$STAMP_DIR"

create_audio_fixture() {
    local path="$1"
    local freq="$2"
    local duration="$3"

    if [[ -f "$path" ]]; then
        return
    fi

    log "creating audio fixture $(basename "$path")"

    if have_cmd ffmpeg; then
        ffmpeg -v error -y \
            -f lavfi -i "sine=frequency=${freq}:duration=${duration}:sample_rate=48000" \
            -ac 2 -c:a pcm_s16le "$path"
        return
    fi

    if have_cmd sox; then
        sox -n -r 48000 -c 2 "$path" synth "$duration" sine "$freq"
        return
    fi

    perl -e '
        use strict;
        use warnings;
        my ($out, $seconds, $rate, $channels) = @ARGV;
        my $bits = 16;
        my $bytes_per_sample = int($bits / 8);
        my $data_size = int($seconds * $rate * $channels * $bytes_per_sample);
        open(my $fh, q{>:raw}, $out) or die "open $out: $!";
        print $fh "RIFF";
        print $fh pack("V", 36 + $data_size);
        print $fh "WAVEfmt ";
        print $fh pack("VvvVVvv", 16, 1, $channels, $rate,
            $rate * $channels * $bytes_per_sample,
            $channels * $bytes_per_sample,
            $bits);
        print $fh "data";
        print $fh pack("V", $data_size);
        print $fh "\0" x $data_size;
        close($fh) or die "close $out: $!";
    ' "$path" "$duration" 48000 2
}

create_ppm_gradient() {
    local path="$1"
    local width="$2"
    local height="$3"

    if [[ -f "$path" ]]; then
        return
    fi

    log "creating image fixture $(basename "$path")"
    {
        printf 'P3\n%d %d\n255\n' "$width" "$height"
        awk -v w="$width" -v h="$height" '
            BEGIN {
                for (y = 0; y < h; y++) {
                    for (x = 0; x < w; x++) {
                        r = int((x * 255) / (w - 1));
                        g = int((y * 255) / (h - 1));
                        b = (x + y) % 256;
                        printf "%d %d %d\n", r, g, b;
                    }
                }
            }
        '
    } > "$path"
}

create_ppm_noise() {
    local path="$1"
    local width="$2"
    local height="$3"
    local seed="$4"

    if [[ -f "$path" ]]; then
        return
    fi

    log "creating image fixture $(basename "$path")"
    {
        printf 'P3\n%d %d\n255\n' "$width" "$height"
        awk -v w="$width" -v h="$height" -v s="$seed" '
            BEGIN {
                srand(s);
                for (y = 0; y < h; y++) {
                    for (x = 0; x < w; x++) {
                        r = int(rand() * 256);
                        g = int(rand() * 256);
                        b = int(rand() * 256);
                        printf "%d %d %d\n", r, g, b;
                    }
                }
            }
        '
    } > "$path"
}

create_database_fixture() {
    local db_dir="$1"

    mkdir -p "$db_dir"

    if [[ -f "$db_dir/sales.csv" && -f "$db_dir/users.csv" && -f "$db_dir/events.ndjson" ]]; then
        return
    fi

    log "creating database-like fixtures"

    {
        printf 'id,user_id,amount_cents,region,created_at\n'
        for i in $(seq 1 120000); do
            printf '%d,%d,%d,region_%02d,%d\n' \
                "$i" "$((1 + (i % 4000)))" "$(((i * 7919) % 100000))" "$((i % 17))" "$((1700000000 + i))"
        done
    } > "$db_dir/sales.csv"

    {
        printf 'user_id,email,plan,active\n'
        for i in $(seq 1 4000); do
            printf '%d,user%04d@example.org,plan_%02d,%s\n' \
                "$i" "$i" "$((i % 6))" "$([[ $((i % 5)) -eq 0 ]] && echo false || echo true)"
        done
    } > "$db_dir/users.csv"

    {
        for i in $(seq 1 80000); do
            printf '{"event_id":%d,"session":"sess_%06d","kind":"evt_%03d","value":%d}\n' \
                "$i" "$((100000 + i))" "$((i % 250))" "$(((i * 3571) % 1000000))"
        done
    } > "$db_dir/events.ndjson"

    if have_cmd sqlite3; then
        sqlite3 "$db_dir/synthetic.sqlite" <<'SQL'
PRAGMA journal_mode=OFF;
PRAGMA synchronous=OFF;
DROP TABLE IF EXISTS metric;
CREATE TABLE metric (
    id INTEGER PRIMARY KEY,
    category TEXT NOT NULL,
    payload TEXT NOT NULL,
    value INTEGER NOT NULL,
    ts INTEGER NOT NULL
);
WITH RECURSIVE seq(i) AS (
    VALUES(1)
    UNION ALL
    SELECT i + 1 FROM seq WHERE i < 120000
)
INSERT INTO metric(category, payload, value, ts)
SELECT
    printf('cat_%03d', i % 400),
    printf('payload_%08d_%08d', i, i * 13),
    (i * 7919) % 1000000,
    1700000000 + i
FROM seq;
CREATE INDEX metric_category_idx ON metric(category);
CREATE INDEX metric_ts_idx ON metric(ts);
SQL
    fi
}

create_source_fixture() {
    local src_dir="$1"
    local include_dir="$src_dir/include"
    local c_dir="$src_dir/c"
    local rust_dir="$src_dir/rust"
    local go_dir="$src_dir/go"

    if [[ -d "$src_dir" ]] && find "$src_dir" -type f -print -quit | grep -q .; then
        return
    fi

    log "creating source-code fixture tree"
    mkdir -p "$include_dir" "$c_dir" "$rust_dir" "$go_dir"

    for i in $(seq 1 180); do
        cat > "$include_dir/module_${i}.h" <<EOT
#ifndef MODULE_${i}_H
#define MODULE_${i}_H

int module_${i}_accumulate(int seed, int rounds);

#endif
EOT

        cat > "$c_dir/module_${i}.c" <<EOT
#include "module_${i}.h"

int module_${i}_accumulate(int seed, int rounds) {
    int v = seed ^ ${i};
    int j;

    for (j = 0; j < rounds; ++j) {
        v = (v * 1103515245 + 12345 + ${i}) & 0x7fffffff;
    }

    return v;
}
EOT

        cat > "$rust_dir/mod_${i}.rs" <<EOT
pub fn compute_${i}(mut v: u64, rounds: u32) -> u64 {
    let mut i = 0;
    while i < rounds {
        v = v.wrapping_mul(6364136223846793005).wrapping_add(${i});
        i += 1;
    }
    v
}
EOT

        cat > "$go_dir/mod_${i}.go" <<EOT
package mods

func Compute${i}(v uint64, rounds uint32) uint64 {
    var i uint32
    for i = 0; i < rounds; i++ {
        v = (v * 2862933555777941757) + uint64(${i})
    }
    return v
}
EOT
    done
}

build_source_fixtures() {
    mkdir -p "$SOURCE_DIR/audio" "$SOURCE_DIR/images" "$SOURCE_DIR/databases" "$SOURCE_DIR/source_code"

    create_audio_fixture "$SOURCE_DIR/audio/tone_a4_12s.wav" 440 12
    create_audio_fixture "$SOURCE_DIR/audio/tone_e5_8s.wav" 659 8
    create_audio_fixture "$SOURCE_DIR/audio/tone_c3_20s.wav" 131 20

    create_ppm_gradient "$SOURCE_DIR/images/gradient_1024.ppm" 1024 1024
    create_ppm_gradient "$SOURCE_DIR/images/gradient_1920x1080.ppm" 1920 1080
    create_ppm_noise "$SOURCE_DIR/images/noise_768.ppm" 768 768 42

    create_database_fixture "$SOURCE_DIR/databases"
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

build_archive() {
    local archive_name="$1"
    shift

    local archive_path="$ARCHIVE_DIR/$archive_name"
    local stamp_path="$STAMP_DIR/$archive_name.stamp"
    local stamp_key="${SOURCE_FINGERPRINT}|$(rar_version)|$*"

    if [[ "$FORCE" -eq 0 && -f "$archive_path" && -f "$stamp_path" ]]; then
        if [[ "$(cat "$stamp_path")" == "$stamp_key" ]]; then
            log "$archive_name: already up to date, skipping"
            return
        fi
    fi

    log "$archive_name: building archive"
    rm -f "$archive_path"
    (
        cd "$SOURCE_DIR"
        "$RAR_BIN" a -idq -ma5 -r "$@" "$archive_path" .
    )
    printf '%s\n' "$stamp_key" > "$stamp_path"
}

build_source_fixtures
SOURCE_FINGERPRINT="$(compute_source_fingerprint)"

build_archive "thematic_store.rar" -m0 -s-
build_archive "thematic_fast.rar" -m1 -s-
build_archive "thematic_best_solid.rar" -m5 -s

log "done: thematic corpus archives are in $ARCHIVE_DIR"
