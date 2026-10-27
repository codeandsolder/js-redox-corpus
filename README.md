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

## Candidate-set semantics

Candidate materialization operates on canonical semantic bodies. A transport body with an `exact:*` representation edge to a browser/runtime source remains in the provenance database, but is excluded from candidate lists so one executed program is not graded twice under two byte representations.

Fatal parser inputs are tracked separately from analyzable residual work:

- `semantic-invalid.txt` / `known-invalid.txt` — final parser-fatal bodies; retained for provenance/diagnostics, not optimization work.
- `semantic-actionable.txt` / `known-residual.txt` — non-fatal bodies with at least one actionable cluster (`actionable_top_score > 0`).
- `semantic-weak-signals.txt` / `known-weak-signals.txt` — non-fatal bodies with actionable primitives that never form a cluster at the configured threshold. Evidence is preserved, but these do not count as residual debt.
- `semantic-zero.txt` / `known-zero.txt` — non-fatal bodies with no actionable signals at all.
- `quick-focus.txt` — clustered residual work worth improving next; weak-only and known-invalid bodies are intentionally excluded.

`semantic-untested.txt` should therefore be empty after a complete semantic pass over the canonical corpus. A non-empty file means genuinely missing semantic work, not an alternate transport representation.
