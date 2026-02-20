# Performance Baseline (Reproducible)

Date: 2026-02-20

Comparator: `unrar -mt1`

## Run profile

- external matrix: `RUNS=7`
- hot-solid stability: `STABLE_REPEATS=3`, `STABLE_RUNS=11`
- warmup enabled in bench scripts
- CPU pinning: `BENCH_CPU_CORE=2`
- threads: `UNRAR_THREADS=1`

## Host profile

- OS: `Linux 6.17.0-14-generic x86_64`
- CPU: `AMD Ryzen 5 5600G with Radeon Graphics` (6C/12T)
- Compiler: `gcc 13.3.0`
- OpenSSL: `3.0.15`

## External Matrix Snapshot

Source report: `docs/perf/external/2026-02-20_153312_external_bench.md`

| Corpus | Mode | Gap % |
|---|---|---:|
| calgary | store | -38.79 |
| calgary | fast | -4.34 |
| calgary | solid | 5.54 |
| calgary | encrypted-data | -14.29 |
| calgary | encrypted-headers | -52.45 |
| canterbury | store | -35.97 |
| canterbury | fast | -0.42 |
| canterbury | solid | 1.47 |
| canterbury | encrypted-data | -17.02 |
| canterbury | encrypted-headers | -58.09 |
| enwik8 | store | 1.12 |
| enwik8 | fast | 0.59 |
| enwik8 | solid | 5.40 |
| enwik8 | encrypted-data | 0.50 |
| enwik8 | encrypted-headers | -4.67 |

Result: hard external gate passes at `TARGET_GAP_PCT=10`.

## Hot Solid Stability Snapshot

Source report: `docs/perf/hot/2026-02-20_153446_hot_solid_stable.md`

- Attempt 1: gap `5.51%`
- Attempt 2: gap `5.91%`
- Attempt 3: gap `6.01%`

Result: stable `<=0%` target is not yet met.

## Notes

- External matrix is stable and within the hard `<=10%` gate.
- Remaining performance focus is `enwik8/solid` single-thread parity/win.
