#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL_ROOT="${CORPUS_LOCAL_ROOT:-$ROOT_DIR/corpus/local}"
SOURCE_DIR="${CORPUS_LOCAL_SOURCE_DIR:-$LOCAL_ROOT/source}"
ARCHIVE_DIR="${CORPUS_LOCAL_ARCHIVE_DIR:-$LOCAL_ROOT/archives}"
STAMP_DIR="${CORPUS_LOCAL_STAMP_DIR:-$LOCAL_ROOT/stamps}"
FORCE=0

if [[ "${1:-}" == "--force" ]]; then
    FORCE=1
fi

log() {
    printf '[corpus-local] %s\n' "$*"
}

die() {
    printf '[corpus-local] error: %s\n' "$*" >&2
    exit 1
}

RAR_BIN="${RAR_BIN:-$("$ROOT_DIR"/scripts/find_rar.sh || true)}"
if [[ -z "$RAR_BIN" ]]; then
    die "rar binary not found. Set RAR_BIN or install rar."
fi

mkdir -p "$SOURCE_DIR" "$ARCHIVE_DIR" "$STAMP_DIR"

create_text_fixture() {
    local path="$1"
    local lines="$2"

    if [[ -f "$path" ]]; then
        return
    fi

    log "creating text fixture $(basename "$path")"
    : > "$path"
    for i in $(seq 1 "$lines"); do
        printf 'line=%06d quick brown fox jumps over the lazy dog %06d\n' "$i" "$i" >> "$path"
    done
}

create_zero_fixture() {
    local path="$1"
    local size_mb="$2"

    if [[ -f "$path" ]]; then
        return
    fi

    log "creating zero fixture $(basename "$path") (${size_mb}MB)"
    dd if=/dev/zero of="$path" bs=1M count="$size_mb" status=none
}

create_random_fixture() {
    local path="$1"
    local size_mb="$2"

    if [[ -f "$path" ]]; then
        return
    fi

    log "creating random fixture $(basename "$path") (${size_mb}MB)"
    dd if=/dev/urandom of="$path" bs=1M count="$size_mb" status=none
}

create_tree_fixture() {
    local tree_dir="$1"
    local file_count=200

    if [[ -d "$tree_dir" ]] && find "$tree_dir" -type f -print -quit | grep -q .; then
        return
    fi

    log "creating directory tree fixture with ${file_count} small files"
    mkdir -p "$tree_dir"
    for i in $(seq 1 "$file_count"); do
        printf 'tree-file-%03d\n' "$i" > "$tree_dir/file_$i.txt"
    done
}

build_source_fixtures() {
    create_text_fixture "$SOURCE_DIR/small_text.txt" 2000
    create_text_fixture "$SOURCE_DIR/medium_text.txt" 30000
    create_zero_fixture "$SOURCE_DIR/zeros_8mb.bin" 8
    create_random_fixture "$SOURCE_DIR/random_8mb.bin" 8
    create_tree_fixture "$SOURCE_DIR/tree"
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

build_archive "local_store.rar" -m0 -s-
build_archive "local_fast.rar" -m1 -s-
build_archive "local_best_solid.rar" -m5 -s

log "done: local corpus archives are in $ARCHIVE_DIR"
