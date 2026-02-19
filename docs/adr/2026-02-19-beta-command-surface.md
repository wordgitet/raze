# ADR: Beta-Prep Command Surface Expansion

- Status: accepted
- Date: 2026-02-19

## Context

Alpha extraction/integrity goals were complete, but beta-prep required broader
CLI compatibility and cross-platform bring-up.

## Decision

- Expand command surface to `x/e/l/lt/t/p`.
- Implement strict, deterministic switch parsing for the supported subset.
- Keep unsupported switches as usage errors instead of silent no-ops.
- Add portability adapters and CMake/presets for multi-OS bring-up.

## Consequences

- CLI parser complexity increases, but behavior becomes testable and explicit.
- Cross-platform build path exists now, while deep validation remains pending.
- RAR5-only scope and deterministic exit-code contract stay unchanged.

