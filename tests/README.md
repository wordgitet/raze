# tests

Test suites for parser, decoder, and end-to-end extraction.
`make test` runs:

- parser units (`vint`, signature scan, block CRC, shared RAR5 file-header parse),
- metadata mapping units (Unix/Windows mode mapping),
- integration extraction/list scenarios,
- compressed extraction parity checks on local and thematic corpora,
- long-path regression (>1024 bytes),
- metadata restore checks (`mtime` + mode),
- CLI compatibility subset checks and strict switch rejection.

Run:

```sh
make test
```
