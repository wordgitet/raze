# Corpus

This directory stores corpus metadata and scripts, not large data files.

## External Corpora

- Manifest: `corpus/manifest.tsv`
- Download target: `corpus/downloads/`
- Extract target: `corpus/upstream/`

`scripts/corpus_fetch.sh` will:

- Skip downloads if an artifact is already present.
- Reuse existing files if checksum is not specified.
- Validate checksum when provided.
- Skip extraction if the extracted directory matches current archive hash.

## Local Corpora

- Source fixture directory: `corpus/local/source/`
- Generated archive directory: `corpus/local/archives/`

`scripts/corpus_build_local.sh` will:

- Build deterministic fixture files.
- Create multiple RAR5 variants using `rar`.
- Skip rebuild if the source fingerprint and options have not changed.
