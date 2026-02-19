# Beta-Prep Readiness Report

## Completed in this milestone

- Command surface expanded to `x/e/l/lt/t/p`.
- Deterministic switch parser added (`src/cli/cli_args.*`).
- Matcher/path behavior engine added (`src/cli/match.*`,
  `src/io/path_transform.*`).
- Extraction/list flows now honor include/exclude/recurse/prefix filters.
- `t` and `p` command execution added.
- Portability adapter layer introduced (`src/platform/posix_*`,
  `src/platform/win_*`).
- CMake + presets added for cross-platform build bring-up.

## Current gates

- `make` passes.
- `make test` passes.
- Existing alpha integrity/safety behavior remains intact.

## Known gaps before Beta tag

- Cross-platform functional gates (macOS/Windows) not yet fully executed in CI.
- `*BSD` and QNX remain experimental compile/smoke targets.
- Full UnRAR switch parity remains out of scope.

## Risk register

- CLI behavior drift risk as switch surface grows: mitigate with parser and
  command tests.
- Cross-platform path semantics variance: mitigate through adapter-backed
  tests per platform.

