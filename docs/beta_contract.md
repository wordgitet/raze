# Beta-Prep Contract

This document defines deterministic behavior for the current beta-prep CLI
surface.

## Deterministic outcomes

- Unsupported or malformed switches return usage-class failure (`exit 2`).
- Unsupported archive features return unsupported-class failure (`exit 3`).
- Archive corruption returns bad-archive failure (`exit 4`) or checksum-class
  failure (`exit 6`) when integrity verification fails.
- Path violations remain hard failures (`exit 5`).

## Extraction path modes

- `x`: preserve archived relative paths.
- `e`: flatten archived paths (basename extraction).
- `-ep`: forces path flattening for `x`/`e` processing.
- `-ad1`: append archive stem to destination root.
- `-ad2`: append archive file name to destination root.

## Matching/filtering behavior

- `-ap<path>` limits entries to matching archive-internal prefix.
- `-n*` includes and `-x*` excludes are evaluated deterministically.
- Exclude masks override include masks.
- `-r` enables recursive matching against full archive paths.

## Testing/printing commands

- `t` decodes/verifies entries without writing output files.
- `p` streams matched file bytes to stdout and preserves deterministic errors.

