# Raze Roadmap (RAR5-First Checklist)

## Goal

Build a fast, modular RAR5 decompressor in C with measurable performance wins
and strong correctness guarantees.

## Principles

- Correctness before optimization.
- RAR5 first, legacy formats later.
- Profile-driven performance work only.
- Small, testable modules over monolithic code.

## Release Stages

- `Alpha`: feature-complete for intended RAR5 scope, still changing.
- `Beta`: behavior/API/CLI mostly stable, broad validation in progress.
- `Stable`: documented, reproducible, and ready for wider adoption.

## Alpha (Current) Checklist

### Foundations and Parsing

- [x] Baseline corpus and benchmark harness.
- [x] Downloadable corpus manifest + scripts.
- [x] Local corpus generation scripts and re-run detection.
- [x] Expanded local corpus matrix (stress fixtures + corrupt variants).
- [x] RAR5 signature scan and SFX-prefixed scan support.
- [x] RAR5 block iteration + vint decode.
- [x] Header CRC validation.
- [x] Main/file/service/endarc parsing coverage.

### Extraction and Decode

- [x] Store extraction path.
- [x] Compressed extraction path (RAR5 methods in current scope).
- [x] Solid stream support.
- [x] Split/multivolume support (`.partN` and legacy `.r00` chain).
- [x] Encrypted data/header support with password flow.
- [x] Path safety guard (reject unsafe extraction paths).
- [x] Overwrite policy and non-tty deterministic behavior.
- [x] Metadata restore basics (`mtime` + mode).

### Integrity and Correctness

- [x] CRC32 verification flow.
- [x] Full RAR5 BLAKE2sp hash-extra parse/list support.
- [x] BLAKE verification for non-split, split packed-part, encrypted,
      and split+encrypted paths.
- [x] Unknown hash types fail as unsupported feature.
- [x] Corruption handling returns deterministic failure codes.

### Hardening and Tooling

- [x] Unit + integration test suite (`make test`).
- [x] Parser-unit gate target.
- [x] ASan/UBSan gate target.
- [x] Fuzz harnesses for parser/decode entrypoints.
- [x] Bounded fuzz smoke target with temp corpus copy behavior.
- [x] Split CI model: fast required PR/push workflow + nightly/manual
      hardening workflow.
- [x] One-command local CI fallback gate (`make ci-local`).

### Performance and Benching

- [x] Bench scripts for store/compressed/solid/split/encrypted.
- [x] Standardized bench reporting (`RUNS=7`, warmup, `p50`/`p90`).
- [x] Existing hard gates preserved where defined.
- [x] Compressed thematic parity target met (p50 gap `<= 0%` vs `unrar -mt1`,
      `RUNS=7`).

### Project Hygiene

- [x] Linux-only + alpha status documented.
- [x] Project license added (`0BSD`).
- [x] Third-party notices documented.
- [x] Legal/provenance note for UnRAR references documented.
- [x] Targeted decoder invariants/safety comments added.

### Alpha Exit Criteria

- [x] `make test` passes on Linux.
- [x] `make test-asan-ubsan` passes in local environment configuration.
- [x] `make fuzz-build USE_ISAL=0` and smoke fuzz run clean for agreed budget.
- [x] Current CLI/exit-code behavior documented and reproducible.

## Beta Checklist

### Stability and Compatibility

- [ ] Freeze and document supported CLI/switch surface for beta.
- [ ] Maintain backward-compatible behavior for all beta-documented switches.
- [ ] Keep deterministic exit-code mapping stable across releases.
- [ ] Publish compatibility matrix (supported vs unsupported archive features).

### Quality and Validation

- [ ] Expand corpus coverage (more real-world and adversarial fixtures).
- [ ] Add regression tests for every fixed bug class (no silent reopenings).
- [ ] Add long-running fuzz jobs (nightly or scheduled) and triage process.
- [ ] Add reproducible benchmark baselines for target hardware classes.

### Performance

- [ ] Profile top decode hotspots with representative corpora.
- [ ] Land low-risk optimizations with no correctness regression.
- [ ] Track and report deltas against `unrar -mt1` per bench family.

### Packaging and Developer UX

- [ ] Add release build profile and debug build profile docs.
- [ ] Improve contributor docs (architecture map + module contracts).
- [ ] Add changelog discipline for beta milestones.

### Cross-Platform Bring-Up

- [ ] Introduce a small portability layer for filesystem/path/time/tty behavior.
- [ ] Remove Linux-only assumptions from CLI and I/O edge paths.
- [ ] Bring up and validate macOS build + test flow.
- [ ] Bring up and validate Windows build + test flow.
- [ ] Add experimental validation path for `*BSD` (best-effort tier).
- [ ] Add experimental validation path for QNX (best-effort tier).
- [ ] Publish platform support tiers:
      Linux/macOS/Windows as target supported, `*BSD`/QNX as experimental.

### Beta Exit Criteria

- [ ] No known high-severity correctness bugs in supported scope.
- [ ] Fuzz/sanitizer runs stable over repeated CI/nightly windows.
- [ ] Benchmark variance understood and tracked.
- [ ] Documentation complete for install/build/test/run and limitations.

## Stable Checklist

### Release Engineering

- [ ] Define versioning policy (SemVer or project-defined equivalent).
- [ ] Establish release checklist (tag, notes, artifacts, verification).
- [ ] Add signed release tags and reproducible build notes.

### Long-Term Reliability

- [ ] Set minimum support policy for toolchains/platform versions.
- [ ] Establish security reporting/response process.
- [ ] Define deprecation policy for CLI behavior changes.

### Ecosystem Readiness

- [ ] Provide distribution-friendly packaging metadata/instructions.
- [ ] Add full legal/compliance verification for all bundled dependencies.
- [ ] Publish performance/correctness statement for stable scope.
- [ ] Promote supported platform matrix from beta draft to stable contract.

### Stable Exit Criteria

- [ ] Multiple beta cycles completed without major regressions.
- [ ] Stable branch policy and maintenance workflow documented.
- [ ] End-user documentation complete and release-tested.
- [ ] Supported platform matrix passes release CI on every stable candidate.
- [ ] Project ready for broad external consumption.

## Current Focus (Near-Term)

1. Expand corpus-driven fuzz seeds around encrypted split boundaries and hash
   extras.
2. Continue hot-path tuning in decode/filter/write loops while keeping
   `make test` green.
3. Add longer fuzz budget jobs and track historical crash triage.
