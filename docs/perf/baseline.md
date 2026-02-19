# Performance Baseline (Reproducible)

Date: 2026-02-19

Comparator: `unrar -mt1`

## Run profile

- `RUNS=7`
- warmup enabled in bench scripts
- CPU pinning: `BENCH_CPU_CORE=2`
- threads: `UNRAR_THREADS=1`

## Host profile

- OS: `Linux 6.17.0-14-generic x86_64`
- CPU: `AMD Ryzen 5 5600G with Radeon Graphics` (6C/12T)
- Compiler: `gcc 13.3.0`
- OpenSSL: `3.0.15`

## Results (p50/p90)

### Store

- `bench_store_baseline.txt`
  - raze: `p50=0.020020s`, `p90=0.020836s`
  - unrar: `p50=0.053350s`, `p90=0.055403s`
  - gap vs unrar: `-62.47%`

### Compressed

- `local_fast.rar`
  - raze: `p50=0.023595s`, `p90=0.029619s`
  - unrar: `p50=0.069332s`, `p90=0.071259s`
  - gap: `-65.97%`
- `thematic_fast.rar`
  - raze: `p50=0.164989s`, `p90=0.166053s`
  - unrar: `p50=0.169251s`, `p90=0.171048s`
  - gap: `-2.52%`

### Solid

- `local_best_solid.rar`
  - raze: `p50=0.076385s`, `p90=0.078881s`
  - unrar: `p50=0.093467s`, `p90=0.094624s`
  - gap: `-18.28%`
- `thematic_best_solid.rar`
  - raze: `p50=0.166296s`, `p90=0.171220s`
  - unrar: `p50=0.177822s`, `p90=0.178865s`
  - gap: `-6.48%`

### Split

- `bench_split_baseline.txt`
  - raze: `p50=0.010908s`, `p90=0.011391s`
  - unrar: `p50=0.011513s`, `p90=0.012061s`
  - gap vs unrar: `-5.25%`

### Encrypted

- `data-encrypted`
  - raze: `p50=0.026946s`, `p90=0.028135s`
  - unrar: `p50=0.032938s`, `p90=0.040524s`
  - gap: `-18.19%`
- `header-encrypted`
  - raze: `p50=0.026625s`, `p90=0.027290s`
  - unrar: `p50=0.057334s`, `p90=0.058142s`
  - gap: `-53.56%`

## Raw logs

- `docs/perf/bench_store_baseline.txt`
- `docs/perf/bench_compressed_baseline.txt`
- `docs/perf/bench_solid_baseline.txt`
- `docs/perf/bench_split_baseline.txt`
- `docs/perf/bench_encrypted_baseline.txt`
