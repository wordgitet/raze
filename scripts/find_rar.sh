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

find_rar() {
	local candidate

	for candidate in rar rar.exe RAR RAR.exe Rar Rar.exe; do
		if try_cmd_name "$candidate"; then
			return 0
		fi
	done

	for candidate in \
		"/c/Program Files/WinRAR/Rar.exe" \
		"/c/Program Files (x86)/WinRAR/Rar.exe" \
		"/cygdrive/c/Program Files/WinRAR/Rar.exe" \
		"/cygdrive/c/Program Files (x86)/WinRAR/Rar.exe" \
		"/mnt/c/Program Files/WinRAR/Rar.exe" \
		"/mnt/c/Program Files (x86)/WinRAR/Rar.exe"
	do
		if print_if_exec "$candidate"; then
			return 0
		fi
	done

	return 1
}

find_rar
