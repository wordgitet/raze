#!/usr/bin/env bash
set -euo pipefail

has_cmd() {
	command -v "$1" >/dev/null 2>&1
}

print_if_exec() {
	local path="$1"
	if [[ -n "$path" && -x "$path" ]]; then
		printf '%s\n' "$path"
		return 0
	fi
	return 1
}

try_cmd_name() {
	local name="$1"
	local path

	if ! has_cmd "$name"; then
		return 1
	fi
	path="$(command -v "$name" 2>/dev/null || true)"
	print_if_exec "$path"
}

find_unrar() {
	local candidate

	for candidate in unrar unrar.exe UNRAR UNRAR.exe UnRAR UnRAR.exe; do
		if try_cmd_name "$candidate"; then
			return 0
		fi
	done

	for candidate in \
		"/c/Program Files/WinRAR/UnRAR.exe" \
		"/c/Program Files (x86)/WinRAR/UnRAR.exe" \
		"/c/Program Files/WinRAR/unrar.exe" \
		"/c/Program Files (x86)/WinRAR/unrar.exe" \
		"/cygdrive/c/Program Files/WinRAR/UnRAR.exe" \
		"/cygdrive/c/Program Files (x86)/WinRAR/UnRAR.exe" \
		"/cygdrive/c/Program Files/WinRAR/unrar.exe" \
		"/cygdrive/c/Program Files (x86)/WinRAR/unrar.exe" \
		"/mnt/c/Program Files/WinRAR/UnRAR.exe" \
		"/mnt/c/Program Files (x86)/WinRAR/UnRAR.exe" \
		"/mnt/c/Program Files/WinRAR/unrar.exe" \
		"/mnt/c/Program Files (x86)/WinRAR/unrar.exe"
	do
		if print_if_exec "$candidate"; then
			return 0
		fi
	done

	return 1
}

find_unrar
