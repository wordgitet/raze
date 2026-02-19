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

- [x] Freeze and document supported CLI/switch surface for beta-prep.
- [x] Maintain backward-compatible behavior for beta-documented switches.
- [x] Keep deterministic exit-code mapping stable across releases.
- [x] Publish compatibility matrix (supported vs unsupported archive features).

### Quality and Validation

- [ ] Expand corpus coverage (more real-world and adversarial fixtures).
- [ ] Add regression tests for every fixed bug class (no silent reopenings).
- [x] Add switch edge-case regressions for beta CLI surface (`-ap`,
      `-n@`, `-x@`, `-ad1`, `-ad2`) including deterministic usage errors.
- [x] Add split encrypted boundary corruption regression (checksum-class
      failure path).
- [x] Add long-running local fuzz soak target + triage process
      (`make fuzz-soak`, `tests/fuzz/TRIAGE.md`).
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

- [x] Introduce a small portability layer for filesystem/path/time/tty behavior.
- [ ] Remove Linux-only assumptions from CLI and I/O edge paths.
- [ ] Bring up and validate macOS build + test flow.
- [x] Bring up and validate Windows build + test flow (MSYS2 UCRT64:
      `make` + `make test`).
- [ ] Add experimental validation path for `*BSD` (best-effort tier).
- [ ] Add experimental validation path for QNX (best-effort tier).
- [x] Publish platform support tiers:
      Linux/Windows as supported in beta-prep, macOS as target (unverified),
      `*BSD`/QNX as experimental.

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

1. Validate new `x/e/l/lt/t/p` command surface on macOS once hardware/runner
   is available; keep Windows regression coverage in MSYS2.
2. Add reproducible benchmark baselines for target hardware classes.
3. Expand corpus coverage with additional real-world/adversarial fixtures.
