# raze

Fast modular RAR5 decompressor project (work in progress).

## Status and Platform

- Project maturity: **alpha** (interfaces and behavior can still change).
- Platform support: **Linux only** for now.

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
- `-p[password]` (`-p` prompts on TTY)
- `-idq`, `-inul`
- `-` (stop switch parsing)

Unsupported switch forms are rejected with usage exit code `2`.

## Test and Bench

```sh
make test
make test-asan-ubsan
make fuzz-build USE_ISAL=0
make fuzz-smoke USE_ISAL=0 RUN_SECS=30
make bench-store
make bench-compressed
make bench-solid
make bench-split
make bench-encrypted
```

Bench scripts pin UnRAR to single-thread by default for fair comparison with
current `raze` decode path:

- Default: `UNRAR_THREADS=1`
- Default: `RUNS=7`
- Override example: `UNRAR_THREADS=8 make bench-compressed`
- Override example: `RUNS=11 make bench-solid`
- Compressed and solid benches perform one warmup run and report `p50`/`p90`.
- Fuzz smoke runs use temporary corpus copies, so repository seed corpora stay
  unchanged.

## CI Policy

- Fast required CI runs on every PR and push to `master`:
  - build + rar-aware test gate + CLI smoke.
- Nightly/manual hardening CI runs separately:
  - ASan/UBSan + bounded fuzz smoke.
- Benchmark jobs are intentionally local/manual only.

## Corpus Workflow

Keep benchmark corpora out of git and generate them on demand.

```sh
# Download external corpora listed in corpus/manifest.tsv.
make corpus-fetch

# Generate local RAR5 corpora using /usr/bin/rar.
make corpus-local

# Generate themed local corpora (audio/images/database/source-code mixes).
make corpus-themed

# Generate expanded stress corpus (small-files, text/binary/db/path/source,
# plus encrypted/split/corrupt variants).
make corpus-expanded

# Do both steps.
make corpus
```

Scripts detect already downloaded/generated artifacts and skip unnecessary work.

## Metadata Behavior (Current)

- Extraction supports RAR5 methods `0..5`, including:
  - single-volume,
  - solid streams,
  - split/multivolume chains (`.partN.rar` and `.rar/.r00/.r01...`),
  - encrypted data (`-p`) and encrypted headers (`-hp`) when built with OpenSSL.
- RAR5 `-htb` integrity is verified for:
  - non-split entries (stored and compressed),
  - split packed parts (`Pack-BLAKE2`),
  - encrypted entries (`BLAKE2 MAC` when hash-key mode is present).
- If both CRC32 and BLAKE2sp are present, both must pass.
- Unknown file-hash types fail with unsupported-feature status (`exit 3`).
- `mtime` and mode are restored for files and directories when available.
- Metadata apply errors are warnings (non-fatal), while data corruption and I/O errors remain fatal.
- Wrong password returns checksum-class failure (`exit 6`).
- Missing password in non-TTY mode fails deterministically (`exit 2`).

## Decoder Invariants

- In `unpack_v50`, block boundaries are strict: decoding continues only while
  bit reader position is inside current block framing.
- Table-less blocks are accepted only after at least one valid Huffman table
  load in the same stream.
- In solid mode, decoder state is reused only when dictionary model is
  compatible; otherwise extraction fails with bad-archive.
- Invalid back-reference distance is handled deterministically (zero fill),
  never with out-of-window memory access.
- Any malformed slot/table/bitstream transition fails with
  `RAZE_STATUS_BAD_ARCHIVE`.

## Diagnostics

- Fatal CLI errors print status plus context when available:
  - format: `raze: <status>: <detail>`
  - example: `raze: io error: cannot open volume '...': No such file or directory`
- Exit code mapping is unchanged and deterministic.
- Encrypted-path stage timings can be enabled for tuning:
  - `RAZE_PROFILE_ENC=1 ./raze x -psecret -opout archive.rar`
  - prints per-entry/archive timings for `kdf`, `decrypt`, `unpack`,
    `hash_verify`, and `write`.

## UnRAR Compatibility Reference

For backward-compatible command/switch behavior, keep this reference in sync:

- `docs/unrar_compat_help.txt`

## License

- Project code in this tree is licensed under `0BSD`. See `LICENSE`.
- Third-party component licensing is documented in
  `THIRD_PARTY_NOTICES.md`.
- Legal/provenance notes for external references are documented in
  `LEGAL.md`.
