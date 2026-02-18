#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_PATH="${1:-$ROOT_DIR/corpus/manifest.tsv}"
DOWNLOAD_DIR="${CORPUS_DOWNLOAD_DIR:-$ROOT_DIR/corpus/downloads}"
UPSTREAM_DIR="${CORPUS_UPSTREAM_DIR:-$ROOT_DIR/corpus/upstream}"

log() {
    printf '[corpus-fetch] %s\n' "$*"
}

die() {
    printf '[corpus-fetch] error: %s\n' "$*" >&2
    exit 1
}

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

file_sha256() {
    sha256sum "$1" | awk '{print $1}'
}

normalize_expected_sha() {
    local value="${1:-}"
    if [[ "$value" == "-" ]]; then
        value=""
    fi
    printf '%s' "$value"
}

download_file() {
    local url="$1"
    local output_file="$2"
    local tmp_file="$output_file.tmp"

    if have_cmd curl; then
        curl -L --fail --retry 3 --output "$tmp_file" "$url"
    elif have_cmd wget; then
        wget -O "$tmp_file" "$url"
    else
        die "either curl or wget is required to download corpora"
    fi

    mv -f "$tmp_file" "$output_file"
}

extract_archive() {
    local archive_path="$1"
    local dest_dir="$2"

    case "$archive_path" in
        *.tar.gz|*.tgz)
            tar -xzf "$archive_path" -C "$dest_dir"
            ;;
        *.tar.xz)
            tar -xJf "$archive_path" -C "$dest_dir"
            ;;
        *.tar.bz2)
            tar -xjf "$archive_path" -C "$dest_dir"
            ;;
        *.tar)
            tar -xf "$archive_path" -C "$dest_dir"
            ;;
        *.zip)
            if ! have_cmd unzip; then
                die "unzip is required to extract $archive_path"
            fi
            unzip -q -o "$archive_path" -d "$dest_dir"
            ;;
        *)
            cp -f "$archive_path" "$dest_dir/"
            ;;
    esac
}

if [[ ! -f "$MANIFEST_PATH" ]]; then
    die "manifest not found: $MANIFEST_PATH"
fi

mkdir -p "$DOWNLOAD_DIR" "$UPSTREAM_DIR"

entry_count=0
while IFS=$'\t' read -r corpus_id url expected_sha; do
    if [[ -z "${corpus_id:-}" || "${corpus_id:0:1}" == "#" ]]; then
        continue
    fi

    if [[ -z "${url:-}" ]]; then
        die "manifest entry '$corpus_id' has empty URL"
    fi

    entry_count=$((entry_count + 1))
    expected_sha="$(normalize_expected_sha "$expected_sha")"

    url_basename="${url##*/}"
    url_basename="${url_basename%%\?*}"
    url_basename="${url_basename%%\#*}"
    archive_path="$DOWNLOAD_DIR/${corpus_id}__${url_basename}"

    if [[ -f "$archive_path" ]]; then
        if [[ -n "$expected_sha" ]]; then
            current_sha="$(file_sha256 "$archive_path")"
            if [[ "$current_sha" == "$expected_sha" ]]; then
                log "$corpus_id: archive already present with expected checksum, skipping download"
            else
                log "$corpus_id: checksum mismatch, re-downloading archive"
                download_file "$url" "$archive_path"
            fi
        else
            log "$corpus_id: archive already present (no checksum configured), skipping download"
        fi
    else
        log "$corpus_id: downloading archive"
        download_file "$url" "$archive_path"
    fi

    if [[ -n "$expected_sha" ]]; then
        current_sha="$(file_sha256 "$archive_path")"
        if [[ "$current_sha" != "$expected_sha" ]]; then
            die "$corpus_id: expected checksum $expected_sha, got $current_sha"
        fi
    else
        log "$corpus_id: checksum not configured in manifest"
    fi

    local_sha="$(file_sha256 "$archive_path")"
    extract_dir="$UPSTREAM_DIR/$corpus_id"
    stamp_file="$extract_dir/.source_sha256"

    if [[ -f "$stamp_file" ]]; then
        stamped_sha="$(cat "$stamp_file")"
    else
        stamped_sha=""
    fi

    has_payload=0
    if [[ -d "$extract_dir" ]] && find "$extract_dir" -mindepth 1 ! -name '.source_sha256' -print -quit | grep -q .; then
        has_payload=1
    fi

    if [[ "$stamped_sha" == "$local_sha" && "$has_payload" -eq 1 ]]; then
        log "$corpus_id: extracted data already matches archive hash, skipping extract"
        continue
    fi

    log "$corpus_id: extracting archive"
    rm -rf "$extract_dir"
    mkdir -p "$extract_dir"
    extract_archive "$archive_path" "$extract_dir"
    printf '%s\n' "$local_sha" > "$stamp_file"
done < "$MANIFEST_PATH"

if [[ "$entry_count" -eq 0 ]]; then
    die "manifest has no data entries"
fi

log "done: processed $entry_count corpus entries"
