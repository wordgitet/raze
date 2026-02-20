# bench

Benchmark harness and corpus definitions for throughput/regression tracking.

Defaults:

- `UNRAR_THREADS=1` (fair single-thread comparator for current `raze` path)
- `RUNS=7`
- one warmup run per tool/archive before timed runs
- reports `p50` and `p90`
- hard fail gates: `bench-store`, `bench-encrypted`, `bench-external`
  (must be <=10% slower by default)
- warning-only target checks: `bench-compressed`, `bench-solid`,
  `bench-split`, `bench-expanded`, `bench-hot-solid`
- `bench-encrypted` prints both `data-encrypted` and `header-encrypted` results
  before the final pass/fail decision.
- `bench-external` covers `calgary`, `canterbury`, and `enwik8` across
  `store`, `fast`, `solid`, `encrypted-data`, and `encrypted-headers`.
- `bench-external` writes a dated markdown report to `docs/perf/external/`.
- `bench-hot-solid` focuses on `enwik8/solid` for faster hot-loop iteration
  and writes a dated markdown report to `docs/perf/hot/`.

Run:

```sh
make bench-store
make bench-compressed
make bench-solid
make bench-hot-solid
make bench-split
make bench-encrypted
make bench-expanded
make bench-external
```

Override examples:

```sh
RUNS=11 make bench-compressed
UNRAR_THREADS=8 make bench-compressed
RUNS=11 make bench-hot-solid
RUNS=11 ENFORCE_GATE=1 TARGET_GAP_PCT=10 make bench-hot-solid
BENCH_CPU_CORE=2 RUNS=11 make bench-hot-solid
BENCH_CPU_CORE=2 RUNS=7 TARGET_GAP_PCT=10 make bench-external
RUNS=3 FORCE_REPACK=1 TARGET_GAP_PCT=15 make bench-external
```
