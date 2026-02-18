# Raze Roadmap (RAR5-First)

## Goal

Build a fast, modular RAR5 decompressor in C with measurable performance wins and strong correctness guarantees.

## Principles

- Correctness before optimization.
- RAR5 first, legacy formats later.
- Profile-driven performance work only.
- Small, testable modules over monolithic code.

## Phase 0: Baseline and Corpus - DONE

### Deliverables

- Reproducible benchmark corpus (small, medium, large archives; solid and non-solid).
- Downloadable external corpus manifest + scripts (kept out of git history).
- Local corpus generation scripts (RAR5 variants) for controlled benchmarks.
- Re-run detection for already downloaded/generated artifacts.
- Baseline numbers from `unrar` on this machine.
- Simple timing harness and result format.

### Exit Criteria

- We can run one command and compare `raze` vs `unrar` throughput and wall time.

## Phase 1: RAR5 Container Parsing - DONE

### Deliverables

- Signature check and archive-open path.
- RAR5 block iteration and variable-length integer decoding.
- Header parsing for main/file/service blocks.
- Header CRC validation.

### Exit Criteria

- `raze` can list archive entries and metadata from valid RAR5 files.
- Parser tests cover valid, truncated, and malformed inputs.

## Phase 2: Minimal Extraction Path - DONE

### Deliverables

- Support extraction for stored/no-compression files first.
- Output path handling and directory creation.
- Metadata basics (timestamps/attributes where practical).

### Exit Criteria

- End-to-end extraction succeeds for a no-compression RAR5 corpus.

## Phase 3: Core RAR5 Decode Engine (Single-Thread) - DONE

### Deliverables

- Bitstream reader and decode tables.
- Main unpack loop for compressed RAR5 file data.
- Sliding window and match/literal handling.
- Data integrity checks on extracted output.

### Exit Criteria

- Correct extraction across mixed real-world RAR5 samples.
- Byte-for-byte output matches `unrar` results.

## Phase 4: Feature Completeness (Prioritized) - IN PROGRESS

### Deliverables

- Solid archive handling. - DONE
- Multivolume support. - DONE
- Optional encrypted archive support (if in scope). - DONE
- Better error handling and diagnostics. - IN PROGRESS

### Exit Criteria

- Chosen feature set is complete and documented.
- Unsupported features fail clearly and safely.

## Phase 5: Performance Pass

### Deliverables

- Profiling runs (`perf`/sampling) on representative corpus.
- Hot-path optimizations: copy loops, bit decode, checksum, allocation patterns.
- Pipeline overlap where useful (read/decode/write).
- Optional SIMD for targeted hotspots.

### Exit Criteria

- Measurable speedup in target scenarios with no correctness regressions.

## Phase 6: Hardening

### Deliverables

- Unit + integration tests integrated in CI.
- Fuzzing targets for parser and decode entrypoints.
- Sanitizer builds (ASan/UBSan) and regression checks.

### Exit Criteria

- Fuzz/sanitizer runs are clean for agreed budgets.
- Release candidate passes full regression suite.

## Immediate Next Steps

1. Run and tune `bench-solid`, `bench-split`, and `bench-encrypted` versus `unrar` (target <=10% gap).
2. Add more corruption/fuzz coverage around split/solid/encrypted transitions.
3. Improve extraction diagnostics while preserving deterministic status codes.
