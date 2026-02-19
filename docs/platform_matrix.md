# Platform Matrix (Beta-Prep)

## Support tiers

| Platform | Tier | Build path | Validation depth |
|---|---|---|---|
| Linux | Supported | `make`, `cmake` | full test + fuzz + benches |
| macOS | Supported target | `cmake` presets | bring-up in progress |
| Windows | Supported target | `cmake` presets | bring-up in progress |
| *BSD | Experimental | POSIX adapter path | compile/smoke target |
| QNX | Experimental | POSIX adapter path | compile/smoke target |

## Notes

- Linux remains source-of-truth for correctness/performance gates.
- Portability layer is under `src/platform/` with `posix_*` and `win_*`
  adapters.
- Cross-platform functional validation is a beta-prep objective and remains
  partially complete.

