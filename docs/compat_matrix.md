# Compatibility Matrix (Beta-Prep)

## Commands

| Command | Status | Notes |
|---|---|---|
| `x` | Supported | Extract with paths. |
| `e` | Supported | Extract without stored paths. |
| `l` | Supported | List archive contents. |
| `lt` | Supported | Technical list output. |
| `t` | Supported | Integrity/decode test without writing files. |
| `p` | Supported | Print matched files to stdout. |

## Switches in this milestone

| Switch | Status | Scope |
|---|---|---|
| `-op<path>`, `-op <path>` | Supported | `x`,`e` |
| `-o+`, `-o-`, `-y` | Supported | `x`,`e` |
| `-ep` | Supported | `x`,`e` |
| `-r` | Supported | matcher recursion |
| `-n<mask>`, `-x<mask>` | Supported | all commands where file matching applies |
| `-n@<list>`, `-x@<list>` | Supported | all commands where file matching applies |
| `-ap<path>` | Supported | archive-internal prefix filter |
| `-ad1`, `-ad2` | Supported | `x`,`e` destination variants |
| `-cfg-` | Supported | compatibility no-op |
| `-idq`, `-idp`, `-idn`, `-inul`, `-ierr` | Supported | message-level compatibility flags |
| malformed/unknown switches | Rejected | deterministic usage error (`exit 2`) |

## RAR5 feature support snapshot

| Feature | Status |
|---|---|
| Store/compressed methods | Supported (`0..5`) |
| Solid streams | Supported |
| Split/multivolume | Supported |
| Encryption (`-p` / `-hp`) | Supported |
| CRC32 + BLAKE2sp integrity | Supported |
| Unknown hash types | Unsupported feature (`exit 3`) |

