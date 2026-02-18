# raze

Fast modular RAR5 decompressor project (work in progress).

## Layout

- `include/raze/`: Public API headers.
- `src/format/rar5/`: RAR5 container parsing.
- `src/decode/`: Decode orchestration and core unpack logic.
- `src/io/`: Input/output and file operations.
- `src/checksum/`: CRC/hash routines.
- `src/crypto/`: Crypto helpers required by format features.
- `src/cli/`: Command-line interface.
- `tests/`: Unit/integration tests.
- `bench/`: Microbenchmarks and corpus benchmarks.

## Build

```sh
make
```

## Run

```sh
./raze --help
./raze l corpus/local/archives/local_store.rar
./raze x -opout corpus/local/archives/local_store.rar
```

V1 extract-compatible switches (UnRAR-style subset):

- `-op<path>` or `-op <path>`
- `-o+`, `-o-`, `-y`
- `-idq`, `-inul`
- `-` (stop switch parsing)

Unsupported switch forms are rejected with usage exit code `2`.

## Test and Bench

```sh
make test
make bench-store
make bench-compressed
```

## Corpus Workflow

Keep benchmark corpora out of git and generate them on demand.

```sh
# Download external corpora listed in corpus/manifest.tsv.
make corpus-fetch

# Generate local RAR5 corpora using /usr/bin/rar.
make corpus-local

# Generate themed local corpora (audio/images/database/source-code mixes).
make corpus-themed

# Do both steps.
make corpus
```

Scripts detect already downloaded/generated artifacts and skip unnecessary work.

## Metadata Behavior (V1)

- Extraction supports RAR5 methods `0..5` for non-solid, non-encrypted, single-volume archives.
- `mtime` and mode are restored for files and directories when available.
- Metadata apply errors are warnings (non-fatal), while data corruption and I/O errors remain fatal.

## UnRAR Compatibility Reference

For backward-compatible command/switch behavior, keep this reference in sync:

- `docs/unrar_compat_help.txt`
