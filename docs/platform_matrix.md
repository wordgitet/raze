# Platform Matrix (Beta-Prep)

## Support tiers

| Platform | Tier | Build path | Validation depth |
|---|---|---|---|
| Linux | Supported | `make`, `cmake` | full test + fuzz + benches |
| Windows | Supported (beta-prep) | `make` (MSYS2 UCRT64), `cmake` | `make` + `make test` validated |
| macOS | Target (unverified) | `cmake` presets | no host/runner validation yet |
| *BSD | Experimental | POSIX adapter path | compile/smoke target |
| QNX | Experimental | POSIX adapter path | compile/smoke target |

## Notes

- Linux remains source-of-truth for correctness/performance gates.
- Windows functional validation currently uses local MSYS2 UCRT64 runs.
- macOS is kept as a target tier but is blocked on hardware/runner access.
- Portability layer is under `src/platform/` with `posix_*` and `win_*`
  adapters.
- Cross-platform functional validation is a beta-prep objective and remains
  partially complete.
