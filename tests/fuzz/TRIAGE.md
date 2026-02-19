# Fuzz Crash Triage

Use this flow after `make fuzz-soak` reports a crash.

## 1) Locate artifact

Artifacts are written to:

`build/fuzz-soak/<timestamp>/artifacts/<target>/`

Example target names:

- `fuzz_vint`
- `fuzz_block_reader`
- `fuzz_file_header`
- `fuzz_unpack_v50`

## 2) Reproduce locally

Run the target binary against the crashing input:

```sh
./build/fuzz/fuzz_file_header build/fuzz-soak/<timestamp>/artifacts/fuzz_file_header/crash-*
```

For stable stack traces, rebuild without LTO and with sanitizers:

```sh
make clean
make USE_ISAL=0 SANITIZE=address,undefined ENABLE_LTO=0 fuzz-build
./build/fuzz/fuzz_file_header build/fuzz-soak/<timestamp>/artifacts/fuzz_file_header/crash-*
```

## 3) Minimize and classify

Minimize with the same fuzzer binary:

```sh
./build/fuzz/fuzz_file_header \
  -minimize_crash=1 \
  -runs=100000 \
  build/fuzz-soak/<timestamp>/artifacts/fuzz_file_header/crash-* \
  > minimized.bin
```

Classify issue type:

- parser bounds/overflow
- decode state misuse
- unsupported-feature path bug
- status/exit mapping regression

## 4) Land regression coverage

- add a focused unit/integration regression in `tests/`
- keep the minimized reproducer in local triage notes
- rerun:

```sh
make test
make test-asan-ubsan USE_ISAL=0
make fuzz-smoke USE_ISAL=0 RUN_SECS=30
```
