# tests

Test suites for parser, decoder, and end-to-end extraction.
`make test` runs:

- parser units (`vint`, signature scan, block CRC, shared RAR5 file-header parse),
- metadata mapping units (Unix/Windows mode mapping),
- integration extraction/list scenarios,
- command-surface checks for `x/e/l/lt/t/p`,
- compressed extraction parity checks on local and thematic corpora,
- split/multivolume extraction checks (`.partN` and legacy `.r00` naming),
- missing-volume failure behavior checks,
- encrypted extraction checks (`-p` and `-hp`) including wrong/missing password paths,
- BLAKE2sp (`-htb`) integrity checks for non-split, split packed-part, encrypted, and split+encrypted archives,
- long-path regression (>1024 bytes),
- metadata restore checks (`mtime` + mode),
- CLI compatibility subset checks (filters/path behavior) and strict
  malformed-switch rejection.

Run:

```sh
make test
```

Hardening helpers:

```sh
make test-asan-ubsan
make fuzz-build USE_ISAL=0
make fuzz-smoke USE_ISAL=0 RUN_SECS=30
```
