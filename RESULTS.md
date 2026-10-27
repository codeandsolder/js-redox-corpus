# Corpus snapshot — 2026-10-27

This is a reproducible progress snapshot for the large `js-redox` browser-JavaScript corpus. Corpus bodies and SQLite databases are intentionally not committed; this file records aggregate results and the code revisions that produced them.

## Revisions

- `js-redox`: `6735d51c5a14a111a48e349715f31641cee32d95`
- `js-redox-corpus` semantic/post-grade and candidate tooling: `95e3ee9`
- semantic scanner contract: `js-sus-scan/v4`
- post-deobfuscation contract: `safe-deob+sus/v2`

## Semantic corpus

After exact transport/runtime representation collapsing, the JavaScript semantic corpus contains **254,075 unique bodies**.

`js-sus-scan/v4` results:

| Result | Bodies |
| --- | ---: |
| No actionable signals | 208,207 |
| Weak signals only (below cluster threshold) | 21,789 |
| Clustered actionable residual | 24,071 |
| Invalid / final fatal parse | 8 |
| Primary parser originally fatal | 2,236 |
| Recovered by browser-compatible fallback | 2,228 |
| Analysis explicitly incomplete because an opaque span was masked | 2,212 |

Recovery breakdown:

- **2,204** browser-legacy call-expression assignment targets. V8 accepts forms such as `f() = value` in classic/sloppy scripts and throws `ReferenceError` only if execution reaches the assignment; Oxc does not model a call expression as an `AssignmentTarget`. The scanner masks only the diagnostic's exact target span in an analysis-only, byte-length-preserving view, records the span as opaque, and keeps the original source authoritative.
- **24** classic-script fallbacks for browser-era syntax such as HTML comments that is invalid in module parsing.
- **8** remain fatal. All eight are network-only script responses, none were captured as executed runtime scripts, and all eight are also rejected by V8 `vm.Script`. They include truncated bundles, malformed regular expressions, missing generated values, and syntactically broken hand-written JavaScript.

The previous `js-sus-scan/v3` contract had **2,236 fatal bodies**. v4 therefore removes **2,228 / 2,236 = 99.64%** of that parser-fatal bucket without accepting a source that V8 rejects.

Candidate materialization now uses the same canonical semantic-body view as grading: exact transport aliases remain in provenance but are excluded from all candidate sets. Weak actionable primitives are retained separately instead of bypassing the scanner's cluster threshold. After the complete v4 pass, `semantic-untested.txt` is **0**, `semantic-invalid.txt` is **8**, `semantic-weak-signals.txt` is **21,789**, `semantic-actionable.txt` is **24,071**, and post-deob `quick-focus.txt` is **24,028**.

## Post-deobfuscation grade

The `safe-deob+sus/v2` ledger contains all **254,075** bodies:

| Result | Bodies |
| --- | ---: |
| No actionable signals | 208,235 |
| Weak signals only (below cluster threshold) | 21,804 |
| Clustered actionable residual | 24,028 |
| Invalid / final fatal parse | 8 |

The previous v1/v3 snapshot was 206,012 zero-residual and 48,063 residual/fatal. Under the v2 accounting, the eight V8-invalid network bodies are tracked separately rather than counted as residual work; parser compatibility alone moves **2,223 bodies** out of the old combined residual/fatal bucket.

The v2 migration copied 251,839 previously non-fatal rows unchanged and re-ran only the 2,236 rows whose v3 scanner result had been fatal.

Residual debt now follows the scanner's own cluster threshold: a body with isolated actionable primitives but `actionable_top_score = 0` is kept in the weak-signals population rather than `quick-focus`. This removes **21,804** below-threshold bodies from the post-deob work queue without discarding their evidence.

## Decode / representation provenance

The catalog currently has **472** transport-to-runtime representation edges:

- **467 exact decoder-equivalent edges**
  - 393 UTF-8 BOM cases
  - 64 WHATWG Windows-1252 cases
  - 10 UTF-8 replacement cases
- **5 weak URL-only correlations**, deliberately not collapsed

Raw transport bytes remain provenance. Once an exact browser-source representation is known, transport bytes are not counted as a second semantic program.

## Safe-deobfuscation coverage

The first full post-grade pass changed 174,423 bodies, but only **19,734** bodies hit an obfuscation-specific transform; the rest were generic normalization such as constant folding and sequence splitting.

Notable high-density recoveries include anti-bot/ad-tech code with thousands of deterministic rewrites in a single body. Across the corpus, `string_array_decode` occurred in only 158 bodies but performed **197,177** individual decodes; `from_char_code_alias` occurred in 52 bodies but performed **21,625** rewrites.

A separate **4,718-body** class is valid classic JavaScript containing `with` scope. `jsvm-safe-core` deliberately refuses to rewrite these because static name resolution is not sound under dynamic `with` scope. This is a policy skip, not an unparsable-input class. Current `js-redox` reports that reason explicitly as `dynamic-with-scope`.

The current post-grade ledger now separates all 6,930 safe-deob rejections explicitly:

- **4,718** `dynamic-with-scope` policy skips
- **2,212** `parse-failure` rejects (2,204 browser-legacy call-assignment sources plus the eight genuinely invalid network responses)
- **0** remaining generic/unknown safe-deob rejection messages

## Validation

For the v4 browser-legacy recovery, the complete old fatal set was checked against Node/V8 classic-script parsing:

- V8 accepts 2,228 / 2,236.
- `sus-scan` v4 recovers exactly those same 2,228.
- V8 rejects the same final eight that v4 leaves fatal.

The engine-side regression suite also covers legacy call-assignment recovery, classic-script fallback, and a genuinely invalid non-call assignment that must remain fatal.

## Operational performance

- No-op semantic resume/corpus accounting dropped from about **97 s** to about **21 s** on the same busy Acer after selective candidate refreshes, contract-scoped snapshots, canonical-body materialization, and an indexed `(nuisance, content_kind, sha256)` JavaScript scan path.
