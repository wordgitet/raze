# Documentation Map and Format Policy

This directory is now the source of truth for project documentation.

## Format Policy

- Default format: `Markdown` (`.md`).
- Allow simple static `HTML` (`.html`) for reference pages when useful.
- Keep `plain text` (`.txt`) only for byte-faithful reference dumps.
- Keep `YAML` (`.yml`) for CI workflows and automation config.
- Keep `TSV/JSON` for machine datasets and generated metadata only.

## Why

- Markdown is easy for humans and AI tooling.
- Plain HTML is acceptable for portable, browser-viewable docs.
- Plain text is useful when we must preserve exact upstream output.
- Structured formats stay limited to machine-oriented files.

## HTML Rules

- Keep HTML docs simple and readable, not fancy.
- Prefer semantic tags (`main`, `section`, `h1`...`h3`, `pre`, `table`).
- Minimal CSS only; no heavy styling frameworks.
- Avoid JavaScript unless there is a strong documentation need.

## Layout

- `docs/rarlab_technote.md`: RAR technical reference used by decoder work.
- `docs/unrar_compat_help.txt`: UnRAR help reference for CLI compatibility.
- `docs/adr/`: architecture decision records (new).

## ADR Rules

- One decision per file in `docs/adr/`.
- Filename format:
  - `YYYY-MM-DD-short-title.md`
- Include:
  - context
  - decision
  - consequences
  - status (`accepted`, `superseded`, `deprecated`)
