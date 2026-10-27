# js-redox-corpus

Large-corpus acquisition, indexing, grading, and evaluation tooling for [js-redox](https://github.com/codeandsolder/js-redox).

This repository owns the **large/unpinned corpus workflow**: per-hash cataloging and provenance, semantic `sus-scan` sweeps, safe-deobfuscation progress ledgers, candidate materialization, classifier sampling, and optional LLM review. The js-redox repository remains focused on the engine, capture/decoding primitives, and small pinned regression corpora.

Corpus bodies and generated databases are intentionally not stored in Git.

Current aggregate results are tracked in [`RESULTS.md`](RESULTS.md).

## Checkout layout

By default the tools expect sibling checkouts:

```text
~/projects/js-redox/
~/projects/js-redox-corpus/
```

Override the engine checkout with `JS_REDOX_ROOT` and the corpus data root with `JS_REDOX_CORPUS_ROOT`.

```bash
export JS_REDOX_ROOT=~/projects/js-redox
export JS_REDOX_CORPUS_ROOT=~/projects/js-redox-corpus/work/scum-corpus-20261007
```

The analyzer binaries are expected under js-redox `.cargo-target-nodebug/release/` unless explicitly overridden on the command line.

## Provenance

The initial tooling was extracted from `codeandsolder/js-redox` after these source commits:

- `78c587d` — incremental preclassification catalog
- `8f894c0` — browser-aware decoding and grading ledger
- `315b3cb` — incremental grading/resume fixes

Analysis rows retain their existing contract identifiers. New default pipeline IDs include both this repository commit and the js-redox engine commit.
