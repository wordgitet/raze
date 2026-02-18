# bench

Benchmark harness and corpus definitions for throughput/regression tracking.

Defaults:

- `UNRAR_THREADS=1` (fair single-thread comparator for current `raze` path)
- `RUNS=7`
- one warmup run per tool/archive before timed runs
- reports `p50` and `p90`
- hard fail gates: `bench-store`, `bench-encrypted` (must be <=10% slower)
- warning-only target checks: `bench-compressed`, `bench-solid`, `bench-split`

Run:

```sh
make bench-store
make bench-compressed
make bench-solid
make bench-split
make bench-encrypted
```

Override examples:

```sh
RUNS=11 make bench-compressed
UNRAR_THREADS=8 make bench-compressed
```
